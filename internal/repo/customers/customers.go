// Package customers is the repository for the portal's view of Stripe
// Customers: which cus_ identifier belongs to which person in which account
// and environment, and the creation intents that make minting one crash-safe.
//
// The intent is the serialization point. One intent may exist per person per
// environment (a partial unique index enforces it), and its idempotency key
// is fixed at insert. Two concurrent requests therefore converge on one
// intent, one key, and — because Stripe deduplicates on the key — one
// Customer. There is no lock; the constraint is the lock.
package customers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the customer tables. Stateless; every method takes
// the connection to run on.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// Intent mirrors one stripe_customer_creation_intents row: the exact request
// that will be (or was) sent to Stripe, persisted before the remote call so a
// crash after it always resumes with the same origin account and key.
type Intent struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Environment   core.StripeEnvironment
	OriginAccount core.AccountRef
	Idempotency   string
	Email         string
	Name          string

	// CustomerID and RemoteCreatedAt are set together once Stripe answers.
	CustomerID      *string
	RemoteCreatedAt *time.Time
}

// EnsureIntent returns the person's intent for this environment, creating it
// if none exists. On conflict the existing row wins — including its origin
// account and idempotency key, which is what makes concurrent callers
// converge on one Customer.
func (r *Repo) EnsureIntent(ctx context.Context, q db.Conn, userID uuid.UUID, env core.StripeEnvironment, origin core.AccountRef, email, name string) (Intent, error) {
	id := uuid.New()
	intent := Intent{}
	err := q.QueryRow(ctx, `
		INSERT INTO stripe_customer_creation_intents (
			id, user_id, environment, origin_account_ref,
			idempotency_key, local_account_id, email, name
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (user_id, environment) WHERE user_id IS NOT NULL DO UPDATE
			SET updated_at = now()
		RETURNING id, user_id, origin_account_ref, idempotency_key,
		          email, name, customer_id, remote_created_at
	`, id, userID, env.String(), origin.String(),
		"custcreate:"+id.String(), userID.String(), email, name).Scan(
		&intent.ID, &intent.UserID, &originScan{&intent.OriginAccount},
		&intent.Idempotency, &intent.Email, &intent.Name,
		&intent.CustomerID, &intent.RemoteCreatedAt,
	)
	if err != nil {
		return Intent{}, fmt.Errorf("customers: ensure intent: %w", db.Normalize(err))
	}
	intent.Environment = env
	return intent, nil
}

// RecordIntentResult stores what Stripe answered. It refuses to overwrite a
// different customer id: two answers for one intent means the idempotency
// discipline failed somewhere, and that must surface, not be papered over.
func (r *Repo) RecordIntentResult(ctx context.Context, q db.Conn, intentID uuid.UUID, customerID string, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE stripe_customer_creation_intents
		SET customer_id = $2, remote_created_at = $3, updated_at = now()
		WHERE id = $1 AND (customer_id IS NULL OR customer_id = $2)
	`, intentID, customerID, at)
	if err != nil {
		return fmt.Errorf("customers: record intent result: %w", db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("customers: intent %s already records a different customer", intentID)
	}
	return nil
}

// CustomerIDFor returns the person's Customer in one account context, or
// db.ErrNotFound.
func (r *Repo) CustomerIDFor(ctx context.Context, q db.Conn, userID uuid.UUID, env core.StripeEnvironment, account core.AccountRef) (string, error) {
	var customerID string
	err := q.QueryRow(ctx, `
		SELECT customer_id FROM stripe_customers
		WHERE user_id = $1 AND environment = $2 AND account_ref = $3
	`, userID, env.String(), account.String()).Scan(&customerID)
	if err != nil {
		return "", fmt.Errorf("customers: customer for %s in %s/%s: %w",
			userID, env.String(), account.String(), db.Normalize(err))
	}
	return customerID, nil
}

// RecordCustomer stores that a Customer was observed in one account context.
// Idempotent: re-observing the same customer is a no-op, and observing a
// different one for the same context trips the unique index, loudly.
func (r *Repo) RecordCustomer(ctx context.Context, q db.Conn, userID uuid.UUID, env core.StripeEnvironment, account core.AccountRef, customerID string, at time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO stripe_customers (id, user_id, environment, account_ref, customer_id, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, environment, account_ref) WHERE user_id IS NOT NULL
			DO NOTHING
	`, uuid.New(), userID, env.String(), account.String(), customerID, at)
	if err != nil {
		return fmt.Errorf("customers: record customer: %w", db.Normalize(err))
	}
	return nil
}

// originScan parses an account_ref column into a core.AccountRef during Scan.
type originScan struct{ dst *core.AccountRef }

func (s *originScan) Scan(src any) error {
	raw, ok := src.(string)
	if !ok {
		return fmt.Errorf("customers: account_ref is %T, want string", src)
	}
	account, err := core.ParseAccountRef(raw)
	if err != nil {
		return err
	}
	*s.dst = account
	return nil
}
