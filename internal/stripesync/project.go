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
		// Failure returns the event for another attempt. The cause is stored
		// on the row, so a human reading the inbox sees why.
		if failErr := p.inbox.Fail(ctx, p.pool.Conn(), event.ID, token, err.Error()); failErr != nil {
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

	newer, err := p.billing.HasNewerObservation(ctx, p.pool.Conn(), p.env, event.Account,
		session.ID, session.RetrievedAt)
	if err != nil {
		return err
	}
	if newer {
		// A fresher observation of this object is already written. Applying
		// this one would move settled state backwards.
		_, err := p.billing.RecordApplication(ctx, p.pool.Conn(), billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: "superseded by a newer observation", ObjectID: session.ID,
			ObservedAt: session.RetrievedAt, Canonical: []byte("{}"),
		})
		return err
	}

	orderID, err := uuid.Parse(session.OrderReference)
	if err != nil {
		return fmt.Errorf("stripesync: session %s carries no usable order reference %q",
			session.ID, session.OrderReference)
	}
	order, err := p.orders.ByCheckoutSession(ctx, p.pool.Conn(), p.env, event.Account, session.ID)
	if err != nil {
		return err
	}
	if order.ID != orderID {
		return fmt.Errorf("stripesync: session %s references order %s but is attached to %s",
			session.ID, orderID, order.ID)
	}

	lines, err := p.orders.Lines(ctx, p.pool.Conn(), order.ID)
	if err != nil {
		return err
	}

	// Every remote read happens HERE, before the transaction opens. WithTx's
	// contract forbids calling Stripe inside the callback for two reasons that
	// both bite: the callback can be invoked more than once under retry, and a
	// transaction held open across network latency holds locks for as long as
	// Stripe takes to answer.
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

	// One transaction, database writes only: the settlement and the record
	// that it happened commit together, so a crash cannot leave state changed
	// with no trace of why.
	err = p.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
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

		_, err := p.billing.RecordApplication(ctx, c, billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: signal, ObjectID: session.ID, OrderID: &order.ID,
			ObservedAt: session.RetrievedAt, Canonical: canonical,
		})
		return err
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

	newer, err := p.billing.HasNewerObservation(ctx, p.pool.Conn(), p.env, event.Account,
		subscription.ID, subscription.RetrievedAt)
	if err != nil {
		return err
	}
	if newer {
		_, err := p.billing.RecordApplication(ctx, p.pool.Conn(), billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: "superseded by a newer observation", ObjectID: subscription.ID,
			ObservedAt: subscription.RetrievedAt, Canonical: []byte("{}"),
		})
		return err
	}

	canonical, _ := json.Marshal(subscription)
	var periodEnd *time.Time
	if !subscription.CurrentPeriodEnd.IsZero() {
		end := subscription.CurrentPeriodEnd
		periodEnd = &end
	}

	return p.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
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

		_, err = p.billing.RecordApplication(ctx, c, billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: signal, ObjectID: subscription.ID,
			ObservedAt: subscription.RetrievedAt, Canonical: canonical,
		})
		return err
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
	// Stripe renders the reference either as a bare id or, when expanded, as an
	// object. Both spellings appear in the wild depending on API version and
	// expansion, so read both rather than assuming.
	switch ref := object["subscription"].(type) {
	case string:
		return ref, nil
	case map[string]any:
		id, _ := ref["id"].(string)
		return id, nil
	}
	return "", nil
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
