package customers_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/testdb"
)

func seedUser(t *testing.T, pool *db.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	sub := "cust-repo-" + id.String()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO users (id, pocket_id_sub, email, email_verified)
		VALUES ($1, $2, $3, true)
	`, id, sub, sub+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Conn().Exec(c, `DELETE FROM stripe_customers WHERE user_id = $1`, id)
		_, _ = pool.Conn().Exec(c, `DELETE FROM stripe_customer_creation_intents WHERE user_id = $1`, id)
		_, _ = pool.Conn().Exec(c, `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// One person, one Customer per context: re-observing the same identifier is
// a quiet no-op, observing a different one is an invariant violation that
// must not be swallowed — a second identifier means the idempotency
// discipline failed upstream, and hiding that hides the failure.
func TestRecordCustomerRefusesAConflictingIdentifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := customers.New()
	userID := seedUser(t, pool)
	now := time.Now().UTC()

	if err := repo.RecordCustomer(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships, "cus_first", now); err != nil {
		t.Fatalf("first observation: %v", err)
	}
	if err := repo.RecordCustomer(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships, "cus_first", now); err != nil {
		t.Fatalf("same-id re-observation must be a no-op, got: %v", err)
	}

	err := repo.RecordCustomer(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships, "cus_other", now)
	if err == nil {
		t.Fatal("a conflicting customer id was accepted silently")
	}
	if !strings.Contains(err.Error(), "different") {
		t.Errorf("error %v does not explain the conflict", err)
	}

	// The stored row must still be the original.
	got, err := repo.CustomerIDFor(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships)
	if err != nil || got != "cus_first" {
		t.Errorf("stored customer = %q (%v), want cus_first", got, err)
	}
}

// Fresh distinguishes "this call minted the intent" from "an earlier attempt
// left it here" — which is what tells EnsureCustomer to reconcile against
// Stripe before daring another create.
func TestEnsureIntentReportsFreshness(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := customers.New()
	userID := seedUser(t, pool)

	first, err := repo.EnsureIntent(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships, "a@example.test", "A")
	if err != nil {
		t.Fatalf("first EnsureIntent: %v", err)
	}
	if !first.Fresh {
		t.Error("the inserting call did not report Fresh")
	}

	second, err := repo.EnsureIntent(ctx, pool.Conn(), userID, core.StripeSandbox, core.Donations, "b@example.test", "B")
	if err != nil {
		t.Fatalf("second EnsureIntent: %v", err)
	}
	if second.Fresh {
		t.Error("a found intent reported Fresh")
	}
	if second.ID != first.ID || second.Idempotency != first.Idempotency {
		t.Error("the second call did not inherit the first intent")
	}
	if second.OriginAccount != core.Memberships {
		t.Errorf("origin account = %v, want the first caller's", second.OriginAccount)
	}
}
