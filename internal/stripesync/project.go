package stripesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
)

// route says how an event type is resolved to local state. Every type listed
// here changes something; anything absent is recorded as ignored.
type route int

const (
	// viaSession resolves through the Checkout Session the event names, to the
	// order it settled. This is money arriving for a purchase.
	viaSession route = iota + 1

	// viaSubscription resolves through the Stripe subscription the event names,
	// to the membership already projected for it. This is the recurring
	// lifecycle: renewal, cancellation, status change.
	viaSubscription
)

// eventRouting is the complete set of events that grant, revoke or retire
// anything. It is short on purpose — Stripe emits dozens of types, and treating
// any of them as authority is how a portal grants access from a page load.
//
// It is also *only* types that actually do something, which it did not use to
// be. Six types were listed as settlement authorities while four of them
// resolved nothing: payment_intent.succeeded, invoice.paid and both
// subscription events carry no Checkout Session, so the session-only resolver
// returned "no local order reference" and recorded them as handled. The visible
// consequence was that renewals never advanced a membership and cancellations
// never revoked one — a member could keep paying and lose access at the end of
// their first period. Recording an event as processed while projecting nothing
// is the worst of the available failures: it is durable and it is silent.
//
// payment_intent.succeeded is deliberately absent rather than routed. Every
// payment in this portal originates from a Checkout Session pinned to cards, so
// it completes synchronously and checkout.session.completed is authoritative for
// one-time money; invoice.paid is authoritative for recurring money. A payment
// intent event would carry nothing those two do not, and a type that resolves
// nothing has no business being called an authority.
var eventRouting = map[string]route{
	"checkout.session.completed":    viaSession,
	"checkout.session.expired":      viaSession,
	"invoice.paid":                  viaSubscription,
	"customer.subscription.updated": viaSubscription,
	"customer.subscription.deleted": viaSubscription,
}

// Projector turns received webhook events into settled local state.
type Projector struct {
	inbox   *inbox.Repo
	orders  *orders.Repo
	billing *billing.Repo
	pool    *db.Pool
	pay     *stripepay.Client
	env     core.StripeEnvironment
	now     func() time.Time
}

// ProjectorOptions configures the projector. Everything is required except Now.
type ProjectorOptions struct {
	Inbox       *inbox.Repo
	Orders      *orders.Repo
	Billing     *billing.Repo
	Pool        *db.Pool
	Pay         *stripepay.Client
	Environment core.StripeEnvironment
	Now         func() time.Time
}

// NewProjector builds the projector, refusing an incomplete configuration.
func NewProjector(opts ProjectorOptions) (*Projector, error) {
	switch {
	case opts.Inbox == nil:
		return nil, errors.New("stripesync: an inbox repository is required")
	case opts.Orders == nil:
		return nil, errors.New("stripesync: an orders repository is required")
	case opts.Billing == nil:
		return nil, errors.New("stripesync: a billing repository is required")
	case opts.Pool == nil:
		return nil, errors.New("stripesync: a database pool is required")
	case opts.Pay == nil:
		return nil, errors.New("stripesync: a Stripe client is required")
	case opts.Environment.IsZero():
		return nil, errors.New("stripesync: a Stripe environment is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Projector{
		inbox: opts.Inbox, orders: opts.Orders, billing: opts.Billing,
		pool: opts.Pool, pay: opts.Pay, env: opts.Environment, now: now,
	}, nil
}

// ProcessOne claims one due event and projects it, reporting whether there was
// anything to do.
//
// The claim/finish protocol is the durability story: a crash anywhere in here
// leaves the row leased, the lease expires, and the next worker picks it up
// again. Every write below is idempotent, so being picked up again is safe.
func (p *Projector) ProcessOne(ctx context.Context, leaseFor time.Duration) (bool, error) {
	event, token, err := p.inbox.Claim(ctx, p.pool.Conn(), p.env, leaseFor, p.now().UTC())
	if errors.Is(err, db.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	via, handled := eventRouting[event.Type]
	if !handled {
		// Recorded as ignored rather than dropped, so "never delivered" and
		// "delivered and irrelevant" stay distinguishable when someone asks
		// why an order did not settle.
		return true, p.inbox.Ignore(ctx, p.pool.Conn(), event.ID, token,
			"event type changes no local state", p.now().UTC())
	}

	if err := p.project(ctx, event, via); err != nil {
		// Failure returns the event for a LATER attempt: Claim reports the
		// attempt number, and Fail turns it into a due time. The cause is stored
		// on the row, so a human reading the inbox sees why.
		if failErr := p.inbox.Fail(ctx, p.pool.Conn(), event.ID, token, err.Error(),
			event.Attempts, p.now().UTC()); failErr != nil {
			return true, fmt.Errorf("%w (and releasing the claim failed: %v)", err, failErr)
		}
		return true, err
	}
	return true, p.inbox.Complete(ctx, p.pool.Conn(), event.ID, token, p.now().UTC())
}

// project does the work for one event: retrieve canonical state, check the
// ordering guard, then write. Which local state it resolves to is the route's
// business.
func (p *Projector) project(ctx context.Context, event inbox.Event, via route) error {
	if via == viaSubscription {
		return p.projectSubscription(ctx, event)
	}

	sessionID, err := p.sessionIDFor(event)
	if err != nil {
		return err
	}
	if sessionID == "" {
		// A session event with no session id: malformed, or Stripe changed the
		// payload shape. Recorded so the guard has a trace, but nothing is
		// projected. This is no longer the routine case it once was — the
		// subscription events that used to land here now have their own route.
		_, err := p.billing.RecordApplication(ctx, p.pool.Conn(), billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: "no session reference on a session event", ObjectID: event.ObjectID,
			ObservedAt: p.now().UTC(), Canonical: []byte("{}"),
		})
		return err
	}

	// The canonical read. Nothing below this line uses the payload: the event
	// said which object changed, and this is what Stripe holds now.
	session, err := p.pay.GetCanonicalSession(ctx, event.Account, sessionID)
	if err != nil {
		return err
	}

	orderID, err := uuid.Parse(session.OrderReference)
	if err != nil {
		return fmt.Errorf("stripesync: session %s carries no usable order reference %q",
			session.ID, session.OrderReference)
	}

	// Every remote read happens HERE, before the transaction opens. WithTx's
	// contract forbids calling Stripe inside the callback for two reasons that
	// both bite: the callback can be invoked more than once under retry, and a
	// transaction held open across network latency holds locks for as long as
	// Stripe takes to answer.
	//
	// The subscription is fetched on the payload's word that this session is
	// paid. The transaction re-decides from canonical state, so a wasted fetch
	// is the only cost of being wrong here.
	var subscription *stripepay.CanonicalSubscription
	if session.PaymentStatus == "paid" && session.SubscriptionID != "" {
		got, err := p.pay.GetCanonicalSubscription(ctx, event.Account, session.SubscriptionID)
		if err != nil {
			return err
		}
		subscription = &got
	}

	canonical, _ := json.Marshal(session)
	signal := "no change"

	// One transaction for every read AND every write that decides anything.
	//
	// The freshness check and the order read used to run on the pool, before
	// this opened, and the transaction then acted on those stale values. Two
	// consequences, both real: concurrent deliveries could each pass the same
	// freshness check because neither had recorded its application yet; and if
	// another worker settled the order in between, Settle returned false while
	// the stale copy still said checkout_pending — so an ordinary duplicate
	// delivery fell into the "paid while not payable" branch and paged a human.
	//
	// The advisory lock is what makes the guard a guard. It serializes every
	// transaction projecting THIS Stripe object, so the freshness check cannot be
	// overtaken between reading and writing. It is keyed on the object rather
	// than the order because the same mechanism has to serve subscription events,
	// which may have no local row to lock at all.
	// The error is a NAMED return because the deferred application record below
	// must be able to surface its own failure. With an unnamed return the defer
	// would assign to a local and the transaction would commit reporting success.
	err = p.pool.WithTx(ctx, db.TxOptions{Lock: objectLock(p.env, event.Account, session.ID)}, func(c db.Conn) (err error) {
		newer, err := p.billing.HasNewerObservation(ctx, c, p.env, event.Account,
			session.ID, session.RetrievedAt)
		if err != nil {
			return err
		}
		if newer {
			// A fresher observation of this object is already written. Applying
			// this one would move settled state backwards.
			signal = "superseded by a newer observation"
			return p.record(ctx, c, event, signal, session.ID, nil, session.RetrievedAt, nil)
		}

		order, err := p.orders.ByCheckoutSession(ctx, c, p.env, event.Account, session.ID)
		if err != nil {
			return err
		}
		if order.ID != orderID {
			return fmt.Errorf("stripesync: session %s references order %s but is attached to %s",
				session.ID, orderID, order.ID)
		}
		lines, err := p.orders.Lines(ctx, c, order.ID)
		if err != nil {
			return err
		}

		defer func() {
			// Recorded on every path, including the escalations. A branch that
			// returned before this left the event with no application row, so the
			// ordering guard had no trace of it and a later delivery could reach
			// the same conclusion again.
			if recErr := p.record(ctx, c, event, signal, session.ID, &order.ID,
				session.RetrievedAt, canonical); recErr != nil && err == nil {
				err = recErr
			}
		}()

		switch {
		case session.Status == "expired":
			abandoned, err := p.orders.Abandon(ctx, c, order.ID, p.now().UTC(),
				"Stripe reported the checkout session expired")
			if err != nil {
				return err
			}
			if abandoned {
				signal = "checkout expired; reservations released"
			}

		case session.PaymentStatus == "paid":
			// Equivalence first: nothing is settled or granted until what Stripe
			// charged matches what the order froze. This is fail-closed by
			// choice. A false positive refuses legitimate money and pages a
			// human, which is recoverable; a false negative grants membership for
			// an amount nobody agreed to, which is not.
			if mismatch := moneyMismatch(order, lines, session); mismatch != "" {
				signal = "money does not match the order; escalated"
				return p.billing.RaiseAlert(ctx, c, p.env, event.Account,
					"settlement_amount_mismatch", "order:"+order.ID.String(),
					"Stripe's charge does not match the order",
					fmt.Sprintf("Order %s was NOT settled and nothing was granted. %s. "+
						"Session %s. Compare the order lines against the Stripe session, "+
						"then settle or refund by hand.",
						order.ID, mismatch, session.ID), p.now().UTC())
			}

			settled, err := p.orders.Settle(ctx, c, order.ID,
				session.PaymentIntentID, session.SubscriptionID, session.InvoiceID, p.now().UTC())
			if err != nil {
				return err
			}
			switch {
			case settled:
				signal = "order settled"
			case order.State == "paid":
				// Already settled by an earlier event about the same payment.
				// Stripe sends several, so this is the ordinary case, and the
				// projections below are idempotent.
				signal = "already settled"
			default:
				// Money arrived for an order that is NOT payable: expired,
				// canceled, refunded. Projecting a membership here would grant
				// something for an order the portal had already given up on —
				// which is how a released reservation becomes an oversold
				// device. Nothing is written; a human is told.
				//
				// Reachable if Stripe accepted a payment on a session the
				// portal failed to expire, so it is a real state rather than a
				// defensive stub.
				signal = "paid while not payable; escalated"
				return p.billing.RaiseAlert(ctx, c, p.env, event.Account,
					"payment_for_unpayable_order", "order:"+order.ID.String(),
					"Payment received for an order that is not awaiting payment",
					fmt.Sprintf("Order %s is %s but Stripe session %s reports paid. "+
						"Refund it or fulfil it by hand; the portal has projected nothing.",
						order.ID, order.State, session.ID), p.now().UTC())
			}
			if err := p.write(ctx, c, order, session, lines, subscription); err != nil {
				return err
			}
		}
		return nil // The deferred record above writes the application row.
	})
	return err
}

// objectLock names the advisory lock that serializes every projection of one
// Stripe object.
//
// Scoped by environment and account as well as id, because a sandbox worker and
// a live worker sharing a database must not block each other, and the same
// identifier in two accounts is two different objects.
func objectLock(env core.StripeEnvironment, account core.AccountRef, objectID string) string {
	return "stripe-projection:" + env.String() + ":" + account.String() + ":" + objectID
}

// record writes the application row that says what this event decided.
//
// Every path through a projection ends here, including the ones that refuse to
// act. An event with no application row is invisible to the ordering guard, so a
// later delivery can reach the same conclusion and raise the same alarm again —
// which is what happened when the escalation branches returned early.
func (p *Projector) record(ctx context.Context, c db.Conn, event inbox.Event,
	signal, objectID string, orderID *uuid.UUID, observedAt time.Time, canonical []byte,
) error {
	if len(canonical) == 0 {
		canonical = []byte("{}")
	}
	_, err := p.billing.RecordApplication(ctx, c, billing.Application{
		Environment: p.env, Account: event.Account,
		StripeEvent: event.StripeID, EventType: event.Type,
		Signal: signal, ObjectID: objectID, OrderID: orderID,
		ObservedAt: observedAt, Canonical: canonical,
	})
	return err
}

// write records what a settled order implies: a membership when it carries a
// subscription, a donation when the money was a gift. Pure database work — the
// canonical objects it needs were already retrieved by the caller.
func (p *Projector) write(ctx context.Context, c db.Conn, order orders.Order, session stripepay.CanonicalSession, lines []orders.Line, subscription *stripepay.CanonicalSubscription) error {
	if subscription != nil {
		membership := billing.Membership{
			UserID: order.UserID, Program: order.Program,
			Environment: p.env, Account: order.Account,
			StripeCustomerID: session.CustomerID, StripeSubscriptionID: subscription.ID,
			Status: subscription.Status, CancelAtPeriodEnd: subscription.CancelAtPeriodEnd,
		}
		if !subscription.CurrentPeriodEnd.IsZero() {
			end := subscription.CurrentPeriodEnd
			membership.CurrentPeriodEnd = &end
		}
		// The anchor: a catalog price version when the tier came from the
		// catalog, otherwise the frozen line the member's own amount lives on.
		// Exactly one, and the schema refuses anything else.
		for _, line := range lines {
			if line.Kind != "hotspot_tier" && line.Kind != "friends_tier" {
				continue
			}
			if line.CatalogPriceVersionID != uuid.Nil {
				id := line.CatalogPriceVersionID
				membership.TierPriceVersionID = &id
			} else {
				id := line.ID
				membership.SourceOrderLineID = &id
			}
			break
		}
		if membership.TierPriceVersionID == nil && membership.SourceOrderLineID == nil {
			return fmt.Errorf("stripesync: order %s settled a subscription with no tier line to anchor it", order.ID)
		}
		if err := p.billing.UpsertMembership(ctx, c, membership); err != nil {
			return err
		}
	}

	// Donations: the donations account is where gifts settle, and a Friends
	// subscription is a gift too. The amount is the order's own frozen total,
	// not the session's — the lines are what the member agreed to.
	if order.Account == core.Donations {
		var total int64
		for _, line := range lines {
			total += line.Amount * int64(line.Quantity)
		}
		if total > 0 {
			if err := p.billing.RecordDonation(ctx, c, order.ID, order.UserID, p.env,
				total, order.Currency, session.PaymentIntentID, p.now().UTC()); err != nil {
				return err
			}
		}
	}
	return nil
}

// moneyMismatch compares what Stripe says it charged against what the order
// froze, returning a human-readable description of the first disagreement or ""
// when they agree.
//
// This is what makes the canonical re-read a control rather than a ceremony.
// Before it existed the projector fetched the session from Stripe and then
// settled on `payment_status == paid` alone, comparing none of the money it had
// just gone to the trouble of reading — while the commit message called that
// "the difference between 'Stripe says' and 'Stripe said once'". Re-reading and
// not comparing is the same as not re-reading.
//
// The comparison is strict on purpose. Amounts come from the local catalog, the
// session is created server-side from frozen lines, and this portal uses no tax,
// no discounts and no proration — so there is no legitimate reason for these to
// differ, and a difference means something is wrong enough to stop for. Note
// what is NOT compared: the shipping address (never stored, per D9) and anything
// derived from the payload rather than the canonical read.
//
// UNVERIFIED AGAINST LIVE STRIPE, and the M6 gate is what verifies it. In
// subscription mode Stripe documents amount_total as the first invoice's total,
// which for a recurring tier plus a one-time device line should be their sum —
// but "should" is doing work in that sentence, and this check is fail-closed, so
// being wrong about it refuses a real member's real payment. The failure is at
// least loud and safe: nothing is granted, nothing is settled, and the alert
// names both numbers, so the first sandbox settlement either passes or tells us
// exactly what Stripe actually reports. Do not relax this to make a gate pass
// without first reading the real session JSON.
func moneyMismatch(order orders.Order, lines []orders.Line, session stripepay.CanonicalSession) string {
	var expected int64
	recurring := false
	for _, line := range lines {
		expected += line.Amount * int64(line.Quantity)
		if line.Kind == "hotspot_tier" || line.Kind == "friends_tier" {
			recurring = true
		}
	}

	if session.AmountTotal != expected {
		return fmt.Sprintf("Stripe charged %d but the order's frozen lines total %d",
			session.AmountTotal, expected)
	}
	if !strings.EqualFold(session.Currency, order.Currency) {
		return fmt.Sprintf("Stripe charged in %s but the order is in %s",
			session.Currency, order.Currency)
	}

	// Mode must match the intent the lines describe. A recurring tier settled in
	// payment mode is a member charged once for a membership that will never
	// renew; a one-off settled in subscription mode is the reverse.
	wantMode := "payment"
	if recurring {
		wantMode = "subscription"
	}
	if session.Mode != wantMode {
		return fmt.Sprintf("Stripe used %s mode but the order's lines describe %s",
			session.Mode, wantMode)
	}
	return ""
}

// projectSubscription applies the recurring lifecycle: a renewal advances the
// membership's period, a cancellation revokes it, a status change records it.
//
// This is the half of M6 that was missing. A renewal arrives as invoice.paid and
// there is NO Checkout Session event alongside it — the session existed once, at
// signup, months ago. So a resolver that only understood sessions meant a member
// who kept paying silently lost access at the end of their first period, and a
// member who cancelled kept it forever.
//
// Like the session path it trusts nothing in the payload beyond the identifier:
// the canonical subscription read is what decides status and period end. An
// invoice event says "something happened to this subscription"; Stripe's current
// view of the subscription says what.
func (p *Projector) projectSubscription(ctx context.Context, event inbox.Event) error {
	subscriptionID, err := p.subscriptionIDFor(event)
	if err != nil {
		return err
	}
	if subscriptionID == "" {
		// An invoice with no subscription is a one-off invoice, which this
		// portal does not issue. Recorded and left alone.
		_, err := p.billing.RecordApplication(ctx, p.pool.Conn(), billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: "no subscription reference", ObjectID: event.ObjectID,
			ObservedAt: p.now().UTC(), Canonical: []byte("{}"),
		})
		return err
	}

	subscription, err := p.pay.GetCanonicalSubscription(ctx, event.Account, subscriptionID)
	if err != nil {
		return err
	}

	canonical, _ := json.Marshal(subscription)
	var periodEnd *time.Time
	if !subscription.CurrentPeriodEnd.IsZero() {
		end := subscription.CurrentPeriodEnd
		periodEnd = &end
	}

	// Same shape as the session path, for the same reason: the freshness check
	// belongs inside the transaction that acts on it, serialized on the object.
	// Without the lock two workers could each find no newer observation and then
	// apply in either order, so an older canonical status could overwrite a newer
	// one — a cancelled membership coming back to life.
	return p.pool.WithTx(ctx, db.TxOptions{Lock: objectLock(p.env, event.Account, subscription.ID)}, func(c db.Conn) error {
		newer, err := p.billing.HasNewerObservation(ctx, c, p.env, event.Account,
			subscription.ID, subscription.RetrievedAt)
		if err != nil {
			return err
		}
		if newer {
			return p.record(ctx, c, event, "superseded by a newer observation",
				subscription.ID, nil, subscription.RetrievedAt, nil)
		}

		applied, err := p.billing.UpdateMembershipLifecycle(ctx, c, p.env, event.Account,
			subscription.ID, subscription.Status, periodEnd, subscription.CancelAtPeriodEnd)
		if err != nil {
			return err
		}

		signal := "membership " + subscription.Status
		if subscription.CancelAtPeriodEnd {
			signal += "; cancels at period end"
		}
		if !applied {
			// No membership for this subscription. Which of two situations this
			// is decides whether anybody needs to be woken up.
			known, err := p.orders.SubscriptionIsKnown(ctx, c, p.env, event.Account, subscription.ID)
			if err != nil {
				return err
			}
			if known {
				// An order settled against this subscription and produced no
				// membership. Money moved and nothing was granted, which is the
				// one failure mode this whole milestone exists to prevent.
				signal = "subscription settled with no membership; escalated"
				if err := p.billing.RaiseAlert(ctx, c, p.env, event.Account,
					"subscription_without_membership", "subscription:"+subscription.ID,
					"A paid subscription has no local membership",
					fmt.Sprintf("Stripe subscription %s is %s and an order is settled "+
						"against it, but no membership row exists. The member is paying "+
						"for access they do not have.", subscription.ID, subscription.Status),
					p.now().UTC()); err != nil {
					return err
				}
			} else {
				// The ordinary race: Stripe sends the first invoice and the
				// checkout session together, and this one arrived first. Nothing
				// is lost by skipping it, because settlement reads canonical
				// subscription state and will record this same period end.
				signal = "no membership yet; initial settlement not processed"
			}
		}

		return p.record(ctx, c, event, signal, subscription.ID, nil,
			subscription.RetrievedAt, canonical)
	})
}

// subscriptionIDFor finds the subscription an event concerns: its own id for a
// subscription event, the referenced one for an invoice.
func (p *Projector) subscriptionIDFor(event inbox.Event) (string, error) {
	if strings.HasPrefix(event.Type, "customer.subscription.") {
		return event.ObjectID, nil
	}
	object, err := event.ObjectFromPayload()
	if err != nil {
		return "", err
	}
	// An invoice's subscription lives under `parent`, not at the top level. On API
	// version 2026-07-29.dahlia a real renewal looks like:
	//
	//	"parent": {
	//	  "type": "subscription_details",
	//	  "subscription_details": { "subscription": "sub_..." }
	//	}
	//
	// This is not a detail I reasoned my way to. The first real Stripe delivery
	// recorded "no subscription reference" and changed nothing, because this
	// function only read object["subscription"] — where older API versions put it
	// — and the test fake echoed that same assumption back, so every lifecycle
	// test agreed with the bug. A renewal would have silently failed to advance
	// any membership in production.
	if parent, ok := object["parent"].(map[string]any); ok {
		if details, ok := parent["subscription_details"].(map[string]any); ok {
			if id := referenceID(details["subscription"]); id != "" {
				return id, nil
			}
		}
	}
	// The legacy top-level spelling, kept because it costs one line and other
	// objects and older versions still use it.
	return referenceID(object["subscription"]), nil
}

// referenceID reads a Stripe reference that may be a bare id or, when expanded,
// an object carrying one.
func referenceID(value any) string {
	switch ref := value.(type) {
	case string:
		return ref
	case map[string]any:
		id, _ := ref["id"].(string)
		return id
	}
	return ""
}

// sessionIDFor finds the Checkout Session an event concerns. Subscription and
// invoice events name their own objects, not a session, so those are resolved
// through the order that already records them.
func (p *Projector) sessionIDFor(event inbox.Event) (string, error) {
	object, err := event.ObjectFromPayload()
	if err != nil {
		return "", err
	}
	switch {
	case event.Type == "checkout.session.completed", event.Type == "checkout.session.expired":
		return event.ObjectID, nil
	case object["checkout_session"] != nil:
		id, _ := object["checkout_session"].(string)
		return id, nil
	default:
		// payment_intent.succeeded, invoice.paid and the subscription events
		// arrive without a session reference. The corresponding
		// checkout.session.completed carries one, and Stripe sends both, so
		// this event needs no independent resolution — recording it is enough.
		return "", nil
	}
}
