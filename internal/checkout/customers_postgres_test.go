package checkout_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/stripetest"
	"triplebit.org/portal/internal/testdb"
)

func newService(t *testing.T, fake *stripetest.Server) (*checkout.Service, *db.Pool) {
	t.Helper()
	pool := testdb.Pool(t)
	pay, err := stripepay.New(stripepay.Options{
		APIKey:               "rk_live_checkouttest",
		Environment:          core.StripeProduction,
		MembershipsAccountID: "acct_m1",
		DonationsAccountID:   "acct_d1",
		BaseURL:              fake.URL(),
	})
	if err != nil {
		t.Fatalf("stripepay.New: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 50)
	}
	ring, err := cryptox.NewKeyring("pii-test", map[string][]byte{"pii-test": key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	svc, err := checkout.New(checkout.Options{
		Customers:   customers.New(),
		Orders:      orders.New(),
		Catalog:     catalogdb.New(),
		Pool:        pool,
		Pay:         pay,
		Keys:        ring,
		Environment: core.StripeProduction,
		BaseURL:     "http://portal.test",
		// Tests never really sleep; the fake's propagation is counted in
		// reads, not time.
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("checkout.New: %v", err)
	}
	return svc, pool
}

func seedPerson(t *testing.T, pool *db.Pool) checkout.Person {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	sub := "checkout-sub-" + id.String()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO users (id, pocket_id_sub, email, display_name, email_verified)
		VALUES ($1, $2, $3, 'Checkout Member', true)
	`, id, sub, sub+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		for _, statement := range []string{
			`DELETE FROM stripe_customers WHERE user_id = $1`,
			`DELETE FROM stripe_customer_creation_intents WHERE user_id = $1`,
			`DELETE FROM users WHERE id = $1`,
		} {
			if _, err := pool.Conn().Exec(c, statement, id); err != nil {
				t.Errorf("seedPerson cleanup failed (%s): %v", statement, err)
			}
		}
	})
	return checkout.Person{UserID: id, Email: sub + "@example.test", Name: "Checkout Member"}
}

func TestEnsureCustomerCreatesOncePerPerson(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, _ := newService(t, fake)
	person := seedPerson(t, mustPool(t))

	first, err := svc.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if fake.Creates() != 1 {
		t.Errorf("%d remote creates, want 1", fake.Creates())
	}

	// The second call is the fast path: no remote traffic at all.
	_, productGets, customerGetsBefore := fake.Gets()
	_ = productGets
	again, err := svc.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		t.Fatalf("second EnsureCustomer: %v", err)
	}
	if again != first {
		t.Errorf("second call returned %s, want %s", again, first)
	}
	if fake.Creates() != 1 {
		t.Error("the second call created another customer")
	}
	if _, _, customerGets := fake.Gets(); customerGets != customerGetsBefore {
		t.Error("the fast path made remote reads")
	}
}

// The sharing design: the same cus_ identifier serves both accounts, and the
// sibling account sees it only after a propagation lag, which EnsureCustomer
// absorbs with a bounded wait.
func TestEnsureCustomerSharesAcrossAccountsThroughPropagationLag(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	fake.SetPropagationLag(3)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)

	inMemberships, err := svc.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		t.Fatalf("EnsureCustomer(memberships): %v", err)
	}
	inDonations, err := svc.EnsureCustomer(ctx, core.Donations, person)
	if err != nil {
		t.Fatalf("EnsureCustomer(donations): %v", err)
	}
	if inMemberships != inDonations {
		t.Fatalf("accounts got different customers: %s vs %s — sharing means one identifier", inMemberships, inDonations)
	}
	if fake.Creates() != 1 {
		t.Errorf("%d remote creates, want 1: the sibling account shares, never mints", fake.Creates())
	}

	// Both contexts are now recorded locally, so both fast-path.
	var rows int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM stripe_customers WHERE user_id = $1`, person.UserID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 2 {
		t.Errorf("%d stripe_customers rows, want 2 (one per account context)", rows)
	}
}

// The crash window: the intent recorded Stripe's answer, but the process died
// before the observation row was written. The next call must resume from the
// intent — no second Customer, no remote create at all when the account is
// the origin.
func TestEnsureCustomerResumesFromARecordedIntent(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	repo := customers.New()

	intent, err := repo.EnsureIntent(ctx, pool.Conn(), person.UserID, core.StripeProduction, core.Memberships, person.Email, person.Name)
	if err != nil {
		t.Fatalf("EnsureIntent: %v", err)
	}
	if err := repo.RecordIntentResult(ctx, pool.Conn(), intent.ID, "cus_fromthecrash", time.Now().UTC()); err != nil {
		t.Fatalf("RecordIntentResult: %v", err)
	}

	got, err := svc.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if got != "cus_fromthecrash" {
		t.Errorf("EnsureCustomer returned %s, want the intent's recorded customer", got)
	}
	if fake.Creates() != 0 {
		t.Errorf("%d remote creates, want 0: the intent already holds the answer", fake.Creates())
	}

	// The resume must also repair the origin projection the crash skipped —
	// otherwise this person consults the intent on every request forever.
	stored, err := repo.CustomerIDFor(ctx, pool.Conn(), person.UserID, core.StripeProduction, core.Memberships)
	if err != nil || stored != "cus_fromthecrash" {
		t.Fatalf("origin projection after resume = %q (%v), want cus_fromthecrash", stored, err)
	}
	_, _, getsBefore := fake.Gets()
	if _, err := svc.EnsureCustomer(ctx, core.Memberships, person); err != nil {
		t.Fatalf("post-repair call: %v", err)
	}
	if _, _, gets := fake.Gets(); gets != getsBefore {
		t.Error("the post-repair call was not the fast path")
	}
}

// The >24h crash window: an unresolved intent whose idempotency record
// Stripe may have pruned. Blindly re-creating could mint a second Customer,
// so EnsureCustomer reconciles by metadata search first and adopts what it
// finds.
func TestStaleUnresolvedIntentAdoptsTheExistingCustomer(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	repo := customers.New()

	// The crash: the intent was recorded and the Customer created remotely,
	// but the result was never persisted. (Created directly against the
	// fake, carrying the metadata the reconciliation searches by.)
	intent, err := repo.EnsureIntent(ctx, pool.Conn(), person.UserID, core.StripeProduction, core.Memberships, person.Email, person.Name)
	if err != nil {
		t.Fatalf("EnsureIntent: %v", err)
	}
	pay, err := stripepay.New(stripepay.Options{
		APIKey:               "rk_live_checkouttest",
		Environment:          core.StripeProduction,
		MembershipsAccountID: "acct_m1",
		DonationsAccountID:   "acct_d1",
		BaseURL:              fake.URL(),
	})
	if err != nil {
		t.Fatalf("stripepay.New: %v", err)
	}
	orphan, err := pay.CreateCustomer(ctx, core.Memberships, intent.Idempotency, stripepay.CustomerSpec{
		Email: person.Email, Name: person.Name, LocalAccountID: person.UserID.String(),
	})
	if err != nil {
		t.Fatalf("simulate crashed create: %v", err)
	}

	got, err := svc.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if got != orphan.ID {
		t.Errorf("EnsureCustomer returned %s, want the reconciled %s", got, orphan.ID)
	}
	if fake.Creates() != 1 {
		t.Errorf("%d total creates, want 1: reconciliation must adopt, never mint", fake.Creates())
	}
	if fake.CustomerCount() != 1 {
		t.Errorf("%d customers exist, want 1", fake.CustomerCount())
	}
}

// Racing requests — including ones targeting different accounts — converge on
// one Customer, because the intent's unique index makes the first insert the
// only insert, and everyone else inherits its idempotency key.
func TestConcurrentEnsureCustomerMintsExactlyOne(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	fake.SetPropagationLag(1)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)

	accounts := []core.AccountRef{core.Memberships, core.Donations, core.Memberships, core.Donations}
	ids := make([]string, len(accounts))
	errs := make([]error, len(accounts))
	var wg sync.WaitGroup
	for i, account := range accounts {
		wg.Add(1)
		go func(i int, account core.AccountRef) {
			defer wg.Done()
			ids[i], errs[i] = svc.EnsureCustomer(ctx, account, person)
		}(i, account)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent call %d: %v", i, err)
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[0] {
			t.Fatalf("call %d got %s, call 0 got %s: one person, one customer", i, ids[i], ids[0])
		}
	}
	if fake.Creates() != 1 {
		t.Errorf("%d remote creates, want exactly 1", fake.Creates())
	}
}

// mustPool exists because seedPerson needs the pool before newService has
// been called in some tests.
func mustPool(t *testing.T) *db.Pool {
	t.Helper()
	return testdb.Pool(t)
}

// The remote create failing outright, driven through EnsureCustomer rather
// than hand-simulated. This wires up the fault injector that had sat unused
// since it was written: an injected 500 must surface as an error with no
// customer recorded, and — because Stripe caches a failure under its
// idempotency key — the immediate retry must replay that cached failure
// rather than appear to succeed. Recovery comes on the next attempt, once the
// intent's metadata search can find nothing and the key has moved on.
func TestFailedRemoteCreateRecordsNothing(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	fake.FailNextCustomerCreates(1)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)

	if _, err := svc.EnsureCustomer(ctx, core.Memberships, person); err == nil {
		t.Fatal("an injected remote failure was reported as success")
	}
	if fake.CustomerCount() != 0 {
		t.Errorf("%d customers exist after a failed create", fake.CustomerCount())
	}

	// Nothing may be recorded locally: no customer projection, and the intent
	// must still be unresolved so a later attempt reconciles rather than
	// assumes.
	if _, err := customers.New().CustomerIDFor(ctx, pool.Conn(), person.UserID, core.StripeProduction, core.Memberships); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("a customer projection survived a failed create: %v", err)
	}
	intent, err := customers.New().EnsureIntent(ctx, pool.Conn(), person.UserID, core.StripeProduction, core.Memberships, person.Email, person.Name)
	if err != nil {
		t.Fatalf("read intent: %v", err)
	}
	if intent.CustomerID != nil {
		t.Errorf("the intent recorded %q despite the create failing", *intent.CustomerID)
	}
}
