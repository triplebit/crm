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

	// Fresh reports whether this call inserted the intent. A found intent
	// that is still unresolved is the crash-window signature: an earlier
	// attempt may have created the Customer remotely without recording it,
	// and Stripe's idempotency records are pruned after ~24 hours — so the
	// caller reconciles against Stripe before daring another create.
	Fresh bool
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
	intent.Fresh = intent.ID == id
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
// Re-observing the same customer is a no-op; observing a DIFFERENT customer
// for the same context is an invariant violation and fails loudly — one
// person has one Customer per environment, and a second identifier appearing
// means the idempotency discipline broke somewhere upstream.
func (r *Repo) RecordCustomer(ctx context.Context, q db.Conn, userID uuid.UUID, env core.StripeEnvironment, account core.AccountRef, customerID string, at time.Time) error {
	// The conflict action only "updates" when the stored id already equals
	// the observed one (a self-assignment), so RowsAffected is 1 for insert
	// and for same-id re-observation, and 0 exactly when a different id is
	// already recorded.
	tag, err := q.Exec(ctx, `
		INSERT INTO stripe_customers (id, user_id, environment, account_ref, customer_id, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, environment, account_ref) WHERE user_id IS NOT NULL
			DO UPDATE SET customer_id = stripe_customers.customer_id
			WHERE stripe_customers.customer_id = EXCLUDED.customer_id
	`, uuid.New(), userID, env.String(), account.String(), customerID, at)
	if db.ConstraintOf(db.Normalize(err)) == "stripe_customers_environment_account_ref_customer_id_key" {
		// ON CONFLICT only absorbs conflicts on its ARBITER index. Two truly
		// simultaneous inserts of the SAME row can still collide on this other
		// unique key: the first inserter writes its index entries one at a
		// time — this constraint's index first, the arbiter's second — and the
		// second inserter's arbiter pre-check can land in the gap between
		// them. It then misses the arbiter, proceeds, and trips over the first
		// inserter's entry here. Demonstrated with a 4-goroutine hammer, which
		// reproduces within a handful of rounds; in CI it surfaced roughly
		// once in dozens of runs and was misattributed to a fake-id collision
		// (see the m6-review-findings CI forensics — the constraint alone
		// cannot distinguish the two, which is why this re-read also names
		// the row's actual owner).
		//
		// The re-read classifies the collision. The same person holding the
		// same customer is the benign race above: the fact this call wanted
		// to record is durably recorded, so this call succeeded in every way
		// that matters. Anyone else holding it is the cross-user invariant
		// violation, reported with the owner named — the diagnostic whose
		// absence made the original CI failure unattributable.
		var ownerUser, ownerGuest *uuid.UUID
		if readErr := q.QueryRow(ctx, `
			SELECT user_id, guest_id FROM stripe_customers
			WHERE environment = $1 AND account_ref = $2 AND customer_id = $3
		`, env.String(), account.String(), customerID).Scan(&ownerUser, &ownerGuest); readErr != nil {
			return fmt.Errorf("customers: record customer: %w (and identifying the conflicting owner failed: %v)",
				db.Normalize(err), readErr)
		}
		if ownerUser != nil && *ownerUser == userID {
			return nil
		}
		owner := "guest"
		if ownerUser != nil {
			owner = "user " + ownerUser.String()
		} else if ownerGuest != nil {
			owner = "guest " + ownerGuest.String()
		}
		return fmt.Errorf("customers: Stripe customer %s in %s/%s already belongs to %s, not user %s",
			customerID, env.String(), account.String(), owner, userID)
	}
	if err != nil {
		return fmt.Errorf("customers: record customer: %w", db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("customers: %s already has a different Stripe customer in %s/%s than %s",
			userID, env.String(), account.String(), customerID)
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
