// Package inbox is the repository for the webhook inbox: durable receipt of
// Stripe events, and leased claims for the worker that projects them.
//
// Receipt and projection are deliberately separate. The HTTP handler's only
// job is to verify a signature and commit the event; everything that could
// fail slowly — retrieving canonical state, writing projections — happens
// later, in a worker, against a row that is already durable. An event Stripe
// delivered can therefore never be lost by a projection bug, and Stripe gets
// its 200 without waiting for our database work.
package inbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the inbox. Stateless; every method takes the
// connection to run on.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// Event is one received Stripe event, as the worker sees it.
type Event struct {
	ID          uuid.UUID
	Environment core.StripeEnvironment
	Account     core.AccountRef
	StripeID    string
	Type        string
	ObjectID    string
	Payload     []byte
	Attempts    int
	MaxAttempts int
}

// ObjectFromPayload decodes the event's object. The payload is verified — the
// signature covered it — so reading it is safe; acting on it is not, which is
// why the projector retrieves the canonical object before writing anything.
// This exists only to read the identifiers that say what to retrieve.
func (e Event) ObjectFromPayload() (map[string]any, error) {
	var envelope struct {
		Data struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(e.Payload, &envelope); err != nil {
		return nil, fmt.Errorf("inbox: decode payload of %s: %w", e.StripeID, err)
	}
	return envelope.Data.Object, nil
}

// Receive stores a verified event, or reports that it was already stored.
//
// Idempotency is the unique index on (environment, account_ref,
// stripe_event_id): Stripe retries deliveries, and a retry must be a no-op
// rather than a second projection. The boolean says which happened, so the
// handler can answer 200 either way while the log can tell them apart.
func (r *Repo) Receive(ctx context.Context, q db.Conn, e Event, receivedAt time.Time, stripeCreatedAt time.Time) (stored bool, err error) {
	tag, err := q.Exec(ctx, `
		INSERT INTO webhook_events (id, environment, account_ref, stripe_event_id,
		    event_type, object_id, payload, stripe_created_at, received_at,
		    processing_state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
		ON CONFLICT (environment, account_ref, stripe_event_id) DO NOTHING
	`, e.ID, e.Environment.String(), e.Account.String(), e.StripeID,
		e.Type, e.ObjectID, e.Payload, stripeCreatedAt, receivedAt)
	if err != nil {
		return false, fmt.Errorf("inbox: receive %s: %w", e.StripeID, db.Normalize(err))
	}
	return tag.RowsAffected() == 1, nil
}

// Claim leases one due event for a worker, or returns db.ErrNotFound when
// there is nothing to do.
//
// FOR UPDATE SKIP LOCKED is the whole design: two workers polling the same
// index take different rows instead of convoying on the oldest one, and a
// worker that dies holds nothing — the row's lease simply expires and
// ReapExpiredLeases returns it. This is the single claim pattern for the
// project; nothing else should invent its own.
func (r *Repo) Claim(ctx context.Context, q db.Conn, env core.StripeEnvironment, leaseFor time.Duration, now time.Time) (Event, uuid.UUID, error) {
	token := uuid.New()
	var e Event
	var account string
	err := q.QueryRow(ctx, `
		WITH claimed AS (
			SELECT id FROM webhook_events
			WHERE environment = $1
			  AND processing_state IN ('pending', 'failed')
			  AND attempts < max_attempts
			ORDER BY received_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE webhook_events w
		SET processing_state = 'processing',
		    lease_token = $2,
		    leased_until = $3::timestamptz + $4::interval,
		    attempts = w.attempts + 1
		FROM claimed
		WHERE w.id = claimed.id
		RETURNING w.id, w.account_ref, w.stripe_event_id, w.event_type,
		          w.object_id, w.payload, w.attempts, w.max_attempts
	`, env.String(), token, now, leaseFor).Scan(
		&e.ID, &account, &e.StripeID, &e.Type, &e.ObjectID, &e.Payload,
		&e.Attempts, &e.MaxAttempts,
	)
	if err != nil {
		return Event{}, uuid.Nil, fmt.Errorf("inbox: claim: %w", db.Normalize(err))
	}
	parsed, err := core.ParseAccountRef(account)
	if err != nil {
		return Event{}, uuid.Nil, err
	}
	e.Account = parsed
	e.Environment = env
	return e, token, nil
}

// Complete marks a claimed event processed. The lease token must match: a
// worker whose lease expired and was reaped must not later overwrite the
// state of a row another worker has since taken.
func (r *Repo) Complete(ctx context.Context, q db.Conn, id, token uuid.UUID, at time.Time) error {
	return r.finish(ctx, q, id, token, "processed", "", &at)
}

// Ignore marks a claimed event as deliberately not projected — an event type
// this portal does not act on. Recorded rather than dropped, so "we never saw
// it" and "we saw it and it does not concern us" stay distinguishable.
func (r *Repo) Ignore(ctx context.Context, q db.Conn, id, token uuid.UUID, reason string, at time.Time) error {
	return r.finish(ctx, q, id, token, "ignored", reason, &at)
}

// Fail releases a claim after a failed attempt. The event returns to 'failed',
// which the claim query still picks up until attempts reaches max_attempts —
// at which point it stops being retried and becomes a job for a human, which
// is what DeadLetters lists.
func (r *Repo) Fail(ctx context.Context, q db.Conn, id, token uuid.UUID, cause string) error {
	return r.finish(ctx, q, id, token, "failed", cause, nil)
}

func (r *Repo) finish(ctx context.Context, q db.Conn, id, token uuid.UUID, state, note string, at *time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE webhook_events
		SET processing_state = $3,
		    last_error = $4,
		    processed_at = COALESCE($5, processed_at),
		    lease_token = NULL,
		    leased_until = NULL
		WHERE id = $1 AND lease_token = $2
	`, id, token, state, note, at)
	if err != nil {
		return fmt.Errorf("inbox: finish %s as %s: %w", id, state, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		// Either the row moved on or this worker's lease was reaped. Either
		// way its work must not be recorded: another worker owns the row.
		return fmt.Errorf("inbox: lease for %s is no longer held: %w", id, db.ErrConflict)
	}
	return nil
}

// ReapExpiredLeases returns events whose worker died mid-flight to 'failed',
// so the claim query finds them again. Without this, a 'processing' row is
// stranded forever — which is exactly what the schema permitted before
// migration 000004 gave it a deadline.
func (r *Repo) ReapExpiredLeases(ctx context.Context, q db.Conn, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE webhook_events
		SET processing_state = 'failed',
		    lease_token = NULL,
		    leased_until = NULL,
		    last_error = 'lease expired; the worker holding it did not finish'
		WHERE processing_state = 'processing' AND leased_until <= $1
	`, now)
	if err != nil {
		return 0, fmt.Errorf("inbox: reap expired leases: %w", db.Normalize(err))
	}
	return tag.RowsAffected(), nil
}

// DeadLetter is an event that has exhausted its attempts.
type DeadLetter struct {
	StripeID  string
	Type      string
	Attempts  int
	LastError string
}

// DeadLetters lists events that will not be retried again. A dead-letter
// queue nobody reads is not a control, so the worker turns these into
// staff_alerts rows; this is the query behind that.
func (r *Repo) DeadLetters(ctx context.Context, q db.Conn, env core.StripeEnvironment, limit int) ([]DeadLetter, error) {
	rows, err := q.Query(ctx, `
		SELECT stripe_event_id, event_type, attempts, last_error
		FROM webhook_events
		WHERE environment = $1 AND processing_state = 'failed'
		  AND attempts >= max_attempts
		ORDER BY received_at
		LIMIT $2
	`, env.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("inbox: dead letters: %w", db.Normalize(err))
	}
	defer rows.Close()

	var out []DeadLetter
	for rows.Next() {
		var d DeadLetter
		if err := rows.Scan(&d.StripeID, &d.Type, &d.Attempts, &d.LastError); err != nil {
			return nil, fmt.Errorf("inbox: scan dead letter: %w", db.Normalize(err))
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inbox: iterate dead letters: %w", db.Normalize(err))
	}
	return out, nil
}
