package stripesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
)

// settlementTypes are the only event types that may move an order to paid.
//
// The list is short on purpose. Stripe emits dozens of types; treating any of
// them as settlement authority is how a portal ends up granting access from a
// page load or a pending intent. A card payment settles on
// payment_intent.succeeded; a subscription's first (and every) period settles
// on invoice.paid; checkout.session.completed is the convenient hook that ties
// either to a local order. Nothing else here grants anything.
var settlementTypes = map[string]bool{
	"checkout.session.completed":    true,
	"payment_intent.succeeded":      true,
	"invoice.paid":                  true,
	"checkout.session.expired":      true,
	"customer.subscription.updated": true,
	"customer.subscription.deleted": true,
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

	if !settlementTypes[event.Type] {
		// Recorded as ignored rather than dropped, so "never delivered" and
		// "delivered and irrelevant" stay distinguishable when someone asks
		// why an order did not settle.
		return true, p.inbox.Ignore(ctx, p.pool.Conn(), event.ID, token,
			"event type is not a settlement authority", p.now().UTC())
	}

	if err := p.project(ctx, event); err != nil {
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
// ordering guard, then write.
func (p *Projector) project(ctx context.Context, event inbox.Event) error {
	sessionID, err := p.sessionIDFor(event)
	if err != nil {
		return err
	}
	if sessionID == "" {
		// Nothing local to tie this to. Recorded so the guard has a trace,
		// but nothing is projected.
		_, err := p.billing.RecordApplication(ctx, p.pool.Conn(), billing.Application{
			Environment: p.env, Account: event.Account,
			StripeEvent: event.StripeID, EventType: event.Type,
			Signal: "no local order reference", ObjectID: event.ObjectID,
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
