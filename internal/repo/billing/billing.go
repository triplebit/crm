// Package billing is the repository for settled financial state: the record
// of which Stripe observations have been applied, and the membership rows
// those observations produce.
//
// Everything here is written only from a canonical object retrieved from
// Stripe, never from a webhook payload, and only after the out-of-order guard
// agrees this observation is newer than the last one applied to the same
// object.
package billing

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the settled-state tables.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// Application is one record of an observation having been applied.
type Application struct {
	Environment core.StripeEnvironment
	Account     core.AccountRef
	StripeEvent string
	EventType   string
	Signal      string
	ObjectID    string
	OrderID     *uuid.UUID

	// ObservedAt is when the canonical object was RETRIEVED — see migration
	// 000004. Ordering by Stripe's event.created would reject exactly the
	// late-delivered event that carries the freshest state.
	ObservedAt time.Time

	// Canonical is the minimized object, retained for a bounded window. It
	// must never carry payment-method, bank or address detail.
	Canonical []byte
}

// HasNewerObservation reports whether some already-applied observation of the
// same object is at least as recent as this one.
//
// This is the out-of-order guard. Stripe does not promise delivery order, so
// two events about one object can arrive reversed; applying the older one
// second would move settled state backwards. Comparing retrieval times means
// the question asked is "is what I hold staler than what is already written?",
// which is the only version of the question that is answerable.
func (r *Repo) HasNewerObservation(ctx context.Context, q db.Conn, env core.StripeEnvironment, account core.AccountRef, objectID string, observedAt time.Time) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM stripe_projection_applications
			WHERE environment = $1 AND account_ref = $2 AND object_id = $3
			  AND observed_at >= $4
		)
	`, env.String(), account.String(), objectID, observedAt).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("billing: check newer observation of %s: %w", objectID, db.Normalize(err))
	}
	return exists, nil
}

// RecordApplication stores that an observation was applied. The unique index
// on (environment, account_ref, stripe_event_id, object_id) makes a replayed
// event a no-op per object rather than a second projection, so the caller can
// treat a false return as "already done".
//
// Object id is part of the key because one settlement event legitimately
// applies to two objects: the Checkout Session it names, and the Subscription
// its membership write was derived from. Recording both is what gives every
// Subscription-derived membership write one ordering domain — the lifecycle
// path's out-of-order guard asks about the subscription's object id, and an
// observation settlement wrote must be visible to that question.
func (r *Repo) RecordApplication(ctx context.Context, q db.Conn, a Application) (bool, error) {
	canonical := a.Canonical
	if len(canonical) == 0 {
		canonical = []byte("{}")
	}
	tag, err := q.Exec(ctx, `
		INSERT INTO stripe_projection_applications (
			id, environment, account_ref, stripe_event_id, event_type, signal,
			object_id, order_id, observed_at, canonical
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (environment, account_ref, stripe_event_id, object_id) DO NOTHING
	`, uuid.New(), a.Environment.String(), a.Account.String(), a.StripeEvent,
		a.EventType, a.Signal, a.ObjectID, a.OrderID, a.ObservedAt, canonical)
	if err != nil {
		return false, fmt.Errorf("billing: record application of %s: %w", a.StripeEvent, db.Normalize(err))
	}
	return tag.RowsAffected() == 1, nil
}

// Membership is a live subscription as the portal records it.
type Membership struct {
	UserID      uuid.UUID
	Program     string
	Environment core.StripeEnvironment
	Account     core.AccountRef

	// Exactly one anchor is set, and the schema enforces it: a catalog price
	// version for a catalog-priced tier, or the frozen order line for a
	// custom-amount Friends subscription, where the member chose the price and
	// no catalog version describes it.
	TierPriceVersionID *uuid.UUID
	SourceOrderLineID  *uuid.UUID

	StripeCustomerID     string
	StripeSubscriptionID string
	Status               string
	CurrentPeriodEnd     *time.Time
	CancelAtPeriodEnd    bool
}

// UpsertMembership projects a subscription, keyed on its Stripe id.
//
// Keying on the subscription rather than the person is deliberate: Stripe owns
// the subscription's lifecycle, and every event about it names that id. A
// second row for the same subscription would mean two records of one truth.
func (r *Repo) UpsertMembership(ctx context.Context, q db.Conn, m Membership) error {
	_, err := q.Exec(ctx, `
		INSERT INTO memberships (
			id, user_id, program, environment, account_ref,
			tier_price_version_id, source_order_line_id,
			stripe_customer_id, stripe_subscription_id, status,
			current_period_end, cancel_at_period_end
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (environment, account_ref, stripe_subscription_id) DO UPDATE SET
			status               = EXCLUDED.status,
			current_period_end   = EXCLUDED.current_period_end,
			cancel_at_period_end = EXCLUDED.cancel_at_period_end,
			updated_at           = now()
	`, uuid.New(), m.UserID, m.Program, m.Environment.String(), m.Account.String(),
		m.TierPriceVersionID, m.SourceOrderLineID,
		m.StripeCustomerID, m.StripeSubscriptionID, m.Status,
		m.CurrentPeriodEnd, m.CancelAtPeriodEnd)
	if err != nil {
		return fmt.Errorf("billing: upsert membership %s: %w", m.StripeSubscriptionID, db.Normalize(err))
	}
	return nil
}

// RecordDonation stores a settled gift. One donation per order (the schema
// makes order_id unique), keyed for replay on the payment intent that settled
// it, so a redelivered event adds nothing.
//
// The tax-acknowledgment amounts — original contribution, refund total — live
// on the acknowledgments table, not here: M9 derives them from this row and
// from refunds rather than duplicating them at settlement time.
func (r *Repo) RecordDonation(ctx context.Context, q db.Conn, orderID, userID uuid.UUID, env core.StripeEnvironment, amount int64, currency, paymentIntentID string, at time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO donations (
			id, order_id, user_id, environment, amount, currency,
			stripe_payment_intent_id, settled_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)
		ON CONFLICT (order_id) DO NOTHING
	`, uuid.New(), orderID, userID, env.String(), amount, currency, paymentIntentID, at)
	if err != nil {
		return fmt.Errorf("billing: record donation for %s: %w", orderID, db.Normalize(err))
	}
	return nil
}

// RaiseAlert records something a human must look at, deduplicated on
// sourceKey so one recurring problem is one row rather than a flood.
//
// A dead-letter queue nobody reads is not a control, which is why this exists
// at all: the worker turns an event that has exhausted its retries into one of
// these, and M7's staff queue shows them.
func (r *Repo) RaiseAlert(ctx context.Context, q db.Conn, env core.StripeEnvironment, account core.AccountRef, kind, sourceKey, title, message string, at time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO staff_alerts (
			id, environment, account_ref, kind, severity, status,
			source_key, title, message, occurred_at
		) VALUES ($1, $2, $3, $4, 'critical', 'open', $5, $6, $7, $8)
		ON CONFLICT (environment, account_ref, source_key) DO UPDATE SET
			message     = EXCLUDED.message,
			occurred_at = EXCLUDED.occurred_at,
			status      = CASE WHEN staff_alerts.status = 'resolved'
			                   THEN 'open' ELSE staff_alerts.status END,
			resolved_at = CASE WHEN staff_alerts.status = 'resolved'
			                   THEN NULL ELSE staff_alerts.resolved_at END,
			updated_at  = now()
	`, uuid.New(), env.String(), account.String(), kind, sourceKey, title, message, at)
	if err != nil {
		return fmt.Errorf("billing: raise alert %s/%s: %w", kind, sourceKey, db.Normalize(err))
	}
	return nil
}

// UpdateMembershipLifecycle applies Stripe's current view of a subscription to
// the membership it already created, reporting whether a row matched.
//
// This is the renewal and cancellation path, and it is deliberately narrower
// than UpsertMembership: it touches only the columns Stripe owns the truth
// about, and it cannot insert. A subscription event carries no user, program or
// price anchor, so a version of this that inserted would have to invent them —
// and a membership conjured from a renewal notice is a membership with no order
// behind it.
//
// The boolean is the interesting part. False means Stripe is telling us about a
// subscription we have no membership for, which the caller must interpret rather
// than ignore: usually the initial settlement simply has not been processed yet.
func (r *Repo) UpdateMembershipLifecycle(ctx context.Context, q db.Conn, env core.StripeEnvironment,
	account core.AccountRef, subscriptionID, status string,
	currentPeriodEnd *time.Time, cancelAtPeriodEnd bool,
) (bool, error) {
	tag, err := q.Exec(ctx, `
		UPDATE memberships
		SET status               = $4,
		    current_period_end   = COALESCE($5, current_period_end),
		    cancel_at_period_end = $6,
		    updated_at           = now()
		WHERE environment = $1 AND account_ref = $2 AND stripe_subscription_id = $3
	`, env.String(), account.String(), subscriptionID, status, currentPeriodEnd, cancelAtPeriodEnd)
	if err != nil {
		return false, fmt.Errorf("billing: update membership for %s: %w", subscriptionID, db.Normalize(err))
	}
	return tag.RowsAffected() == 1, nil
}
