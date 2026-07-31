package customers_test

import (
	"context"
	"strings"
	"sync"
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

// Concurrent identical observations must all succeed.
//
// The serial no-op is already covered above; this covers the case a member
// actually produces by double-clicking Enroll, where several requests record
// the same observation at once. The row violates two unique constraints when it
// already exists — the ON CONFLICT arbiter, and the table's UNIQUE
// (environment, account_ref, customer_id) — and PostgreSQL's ON CONFLICT only
// absorbs conflicts on its ARBITER. The first inserter writes its index
// entries one at a time, the customer-id key's first; a second inserter whose
// arbiter pre-check lands in the gap between them misses the arbiter, then
// trips over the first entry and raises 23505 on
// stripe_customers_environment_account_ref_customer_id_key.
//
// That is the exact failure CI produced in run 30580126989 and again on
// e6c1273's run — one person, one fake, no id collision required. The original
// forensics attributed it to two fakes minting one customer id, a hypothesis
// this test's single round could neither confirm nor refute because the loss
// window is microseconds. It now runs enough rounds to hit the window reliably
// (a hammer reproduced the pre-fix failure within a handful of rounds), so it
// fails against the unfixed RecordCustomer instead of flaking once a month in
// CI. RecordCustomer absorbs the collision by re-reading the row: same owner,
// same customer means the fact is durably recorded and the call succeeded.
func TestConcurrentIdenticalObservationsAllSucceed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := customers.New()
	userID := seedUser(t, pool)
	now := time.Now().UTC()

	const writers, rounds = 8, 150
	for round := range rounds {
		customerID := "cus_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		start := make(chan struct{})
		errs := make(chan error, writers)
		var wg sync.WaitGroup
		for range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // Release them together, to make the race likely.
				errs <- repo.RecordCustomer(ctx, pool.Conn(), userID,
					core.StripeSandbox, core.Memberships, customerID, now)
			}()
		}
		close(start)
		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: a concurrent identical observation failed: %v", round, err)
			}
		}

		// Exactly one row, and it is the observation everybody made.
		var rows int
		if err := pool.Conn().QueryRow(ctx,
			`SELECT count(*) FROM stripe_customers WHERE user_id = $1`, userID).Scan(&rows); err != nil {
			t.Fatalf("round %d: count rows: %v", round, err)
		}
		if rows != 1 {
			t.Fatalf("round %d: %d rows for one person in one account, want 1", round, rows)
		}
		got, err := repo.CustomerIDFor(ctx, pool.Conn(), userID, core.StripeSandbox, core.Memberships)
		if err != nil || got != customerID {
			t.Fatalf("round %d: stored customer = %q (%v), want %q", round, got, err, customerID)
		}
		// A fresh customer id per round needs a fresh slate; the cleanup error
		// is checked because a silently failing DELETE is how this project
		// once leaked rows for weeks.
		if _, err := pool.Conn().Exec(ctx,
			`DELETE FROM stripe_customers WHERE user_id = $1`, userID); err != nil {
			t.Fatalf("round %d: cleanup: %v", round, err)
		}
	}
}

// A collision with somebody ELSE holding the customer id stays loud — and now
// names the owner. The original CI forensics stalled precisely because the
// error preserved only the constraint name: fake-id collision, cleanup leak,
// and the benign same-user race above all produce identical output without
// the owning row's identity. This is the diagnostic that was missing.
func TestCrossUserCustomerCollisionNamesTheOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := customers.New()
	first := seedUser(t, pool)
	second := seedUser(t, pool)
	now := time.Now().UTC()
	customerID := "cus_" + strings.ReplaceAll(uuid.NewString(), "-", "")

	if err := repo.RecordCustomer(ctx, pool.Conn(), first, core.StripeSandbox, core.Memberships, customerID, now); err != nil {
		t.Fatalf("first user's observation: %v", err)
	}
	err := repo.RecordCustomer(ctx, pool.Conn(), second, core.StripeSandbox, core.Memberships, customerID, now)
	if err == nil {
		t.Fatal("a second user recorded somebody else's Stripe customer without complaint")
	}
	for _, want := range []string{customerID, first.String(), second.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q; an unattributable conflict is what made the CI failure undiagnosable", err, want)
		}
	}
}
