package checkout_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/stripetest"
	"triplebit.org/portal/internal/testdb"
)

// seedTier inserts an active catalog item with a verified open price version.
// Slugs are unique per test; the device add-on uses the fixed slug the service
// resolves. Nothing seeds stock: the portal tracks no inventory.
func seedTier(t *testing.T, pool *db.Pool, slug, kind string, recurring bool) catalogdb.Item {
	t.Helper()
	ctx := context.Background()
	repo := catalogdb.New()

	// Self-healing: a crashed earlier run may have leaked this slug's rows,
	// and the open-version unique index would refuse the seed. Deleting is
	// fragile (leaked orders hold foreign keys into the catalog), so leaked
	// open versions are closed instead — harmless history — and the
	// Never trust the previous run's
	// cleanup.
	_, _ = pool.Conn().Exec(ctx, `
		UPDATE catalog_price_versions SET active_until = now()
		WHERE active_until IS NULL
		  AND catalog_item_id IN (SELECT id FROM catalog_items WHERE slug = $1)
	`, slug)

	item, err := repo.UpsertItem(ctx, pool.Conn(), catalogdb.Item{
		Slug: slug, Name: "Test " + slug, Kind: kind,
		Program:          "hotspot",
		RequiresShipping: true, RequiresIMEI: true,
	})
	if err != nil {
		t.Fatalf("seed item %s: %v", slug, err)
	}

	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")
	version := catalogdb.PriceVersion{
		CatalogItemID: item.ID,
		Environment:   core.StripeProduction,
		Account:       core.Memberships,
		ProductID:     "prod_" + suffix,
		PriceID:       "price_" + suffix,
		Amount:        7500, Currency: "usd",
		Recurring:  recurring,
		ActiveFrom: time.Now().UTC(),
	}
	if recurring {
		version.Interval, version.IntervalCount = "month", 1
	}
	versionID, err := repo.InsertPriceVersion(ctx, pool.Conn(), version)
	if err != nil {
		t.Fatalf("seed version %s: %v", slug, err)
	}
	if err := repo.MarkVerified(ctx, pool.Conn(), versionID, time.Now().UTC(), nil); err != nil {
		t.Fatalf("verify version %s: %v", slug, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		// Close rather than delete, for the same foreign-key reason as the
		// upfront sweep; the next run's sweep handles the rest.
		_, _ = pool.Conn().Exec(c, `
			UPDATE catalog_price_versions SET active_until = now()
			WHERE active_until IS NULL AND catalog_item_id = $1
		`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_price_versions WHERE catalog_item_id = $1`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_items WHERE id = $1`, item.ID)
	})
	return item
}

// cleanupOrders registers the order teardown. It must be registered AFTER the
// user seed so it runs BEFORE it (cleanup is LIFO): orders reference users, so
// the user cannot go first.
func cleanupOrders(t *testing.T, pool *db.Pool, userID uuid.UUID) {
	t.Cleanup(func() { testdb.PurgeOrders(t, pool, userID) })
}

// enrollment is the BYOD shape: the member's own device, so an IMEI. A
// device order leaves it blank — staff record it from the unit shipped.
func enrollment(slug string) checkout.EnrollmentRequest {
	return checkout.EnrollmentRequest{
		TierSlug: slug,
		IMEI:     "356938035643809",
	}
}

func TestStartEnrollmentReachesCheckout(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	seedTier(t, pool, "hotspot-device", "device", false)
	cleanupOrders(t, pool, person.UserID)

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = "" // we are shipping the device; staff record its IMEI
	url, err := svc.StartEnrollment(ctx, person, req)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	if url == "" {
		t.Fatal("no checkout URL returned")
	}

	// The order: pending, session attached, both lines frozen with the
	// version identifiers they were sold under, encrypted PII present.
	var state, sessionID, imei, shipping string
	var orderID uuid.UUID
	if err := pool.Conn().QueryRow(ctx, `
		SELECT id, state, COALESCE(stripe_checkout_session_id, ''),
		       COALESCE(imei_ciphertext, ''), COALESCE(shipping_address_ciphertext, '')
		FROM orders WHERE user_id = $1
	`, person.UserID).Scan(&orderID, &state, &sessionID, &imei, &shipping); err != nil {
		t.Fatalf("read order: %v", err)
	}
	if state != "checkout_pending" || sessionID == "" {
		t.Errorf("order state=%s session=%q; want checkout_pending with a session", state, sessionID)
	}
	// This order buys a device, so no member-supplied IMEI; and the shipping
	// address belongs to Stripe's page until M6 projects it. Both empty is
	// the correct pre-settlement state.
	if imei != "" {
		t.Errorf("a device order stored an IMEI (%q); staff record it at fulfillment", imei)
	}
	if shipping != "" {
		t.Errorf("a shipping address was stored before settlement: %q", shipping)
	}

	var lines int
	var lineAmountSum int64
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*), COALESCE(sum(amount), 0) FROM order_lines WHERE order_id = $1
	`, orderID).Scan(&lines, &lineAmountSum); err != nil {
		t.Fatalf("count lines: %v", err)
	}
	if lines != 2 || lineAmountSum != 15000 {
		t.Errorf("lines=%d sum=%d; want 2 lines totalling 15000", lines, lineAmountSum)
	}
	// The Stripe side: subscription mode, the member's customer, the order
	// reference, and card-only pinned by the wrapper.
	if got := fake.Session(sessionID, "mode"); got != "subscription" {
		t.Errorf("session mode = %q, want subscription", got)
	}
	if got := fake.Session(sessionID, "client_reference_id"); got != orderID.String() {
		t.Errorf("client_reference_id = %q, want the order id", got)
	}
}

// The manual out-of-stock lever, end to end. There is no inventory counter —
// hotspots come from a supplier that does not run out — so the only way to stop
// selling something is catalog_items.active, and this proves that flipping it
// refuses the enrolment with a member-visible message and leaves nothing behind.
//
// It replaces a test that proved the schema's reserved <= on_hand check rolled
// an oversell back. That check guarded a subsystem this portal no longer has,
// and which had never worked in production anyway: no code seeded an inventory
// row, so a fresh database refused every hotspot enrolment as out of stock.
func TestStartEnrollmentRefusesAnItemMarkedOutOfStock(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	device := seedTier(t, pool, "hotspot-device", "device", false)
	cleanupOrders(t, pool, person.UserID)

	changed, err := catalogdb.New().SetItemAvailability(ctx, pool.Conn(), device.Slug, false)
	if err != nil {
		t.Fatalf("mark out of stock: %v", err)
	}
	if !changed {
		t.Fatal("the device was already out of stock, so this test proves nothing")
	}

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = ""
	_, err = svc.StartEnrollment(ctx, person, req)
	if err == nil {
		t.Fatal("an item marked out of stock was sold")
	}
	if !safeerr.IsSafe(err) {
		t.Errorf("out-of-stock error %v is not member-visible", err)
	}

	var orphans int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE user_id = $1`, person.UserID).Scan(&orphans); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d order rows survived a refused enrolment", orphans)
	}
	if fake.SessionCount() != 0 {
		t.Error("a checkout session was created for a refused order")
	}

	// And the tier alone still sells: the lever is per item, not a global stop.
	if _, err := svc.StartEnrollment(ctx, person, enrollment(tier.Slug)); err != nil {
		t.Errorf("BYOD enrolment refused while only the device is out of stock: %v", err)
	}
}

// The crash window: order committed, session never attached. The next
// attempt resumes — same order, same idempotency key, so Stripe replays the
// same session rather than minting a second.
func TestStartEnrollmentResumesTheCrashWindow(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	cleanupOrders(t, pool, person.UserID)

	url1, err := svc.StartEnrollment(ctx, person, enrollment(tier.Slug))
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	// Simulate the crash: strip the attached session, as if the process died
	// between Stripe answering and the UPDATE committing.
	if _, err := pool.Conn().Exec(ctx, `
		UPDATE orders SET stripe_checkout_session_id = NULL, checkout_url_expires_at = NULL
		WHERE user_id = $1
	`, person.UserID); err != nil {
		t.Fatalf("simulate crash: %v", err)
	}

	// Advance the clock past any plausible same-second coincidence. The
	// original resume test passed only because both attempts landed inside
	// one second, which hid a session parameter derived from time.Now: the
	// replay then differed from the original and Stripe refused the key with
	// idempotency_error. Found in the sandbox, not here — hence the clock.
	svc.SetClockForTest(func() time.Time { return time.Now().Add(90 * time.Second) })

	url2, err := svc.StartEnrollment(ctx, person, enrollment(tier.Slug))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if url2 != url1 {
		t.Errorf("resume returned a different URL: %q vs %q", url2, url1)
	}
	if fake.SessionCount() != 1 {
		t.Errorf("%d sessions exist, want 1: the resume must replay, not mint", fake.SessionCount())
	}

	var orders int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE user_id = $1`, person.UserID).Scan(&orders); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if orders != 1 {
		t.Errorf("%d orders, want 1", orders)
	}
}

func TestStartEnrollmentValidation(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	cleanupOrders(t, pool, person.UserID)

	badIMEI := enrollment(tier.Slug)
	badIMEI.IMEI = "not-an-imei"
	if _, err := svc.StartEnrollment(ctx, person, badIMEI); err == nil ||
		safeerr.StatusOf(err, 0) != http.StatusUnprocessableEntity {
		t.Errorf("bad IMEI: %v", err)
	}

	// A device order must not carry a member-supplied IMEI: staff record the
	// IMEI of the unit actually shipped, and two sources for one fact is the
	// mistake this codebase exists to avoid.
	deviceWithIMEI := enrollment(tier.Slug)
	deviceWithIMEI.IncludeDevice = true
	if _, err := svc.StartEnrollment(ctx, person, deviceWithIMEI); err == nil || !safeerr.IsSafe(err) {
		t.Errorf("device order with an IMEI: %v", err)
	}

	if _, err := svc.StartEnrollment(ctx, person, enrollment("no-such-tier")); err == nil ||
		safeerr.StatusOf(err, 0) != http.StatusNotFound {
		t.Errorf("unknown tier: %v", err)
	}

	if fake.SessionCount() != 0 {
		t.Error("validation failures reached Stripe")
	}
}

// A pending order past the reservation window must not be resurrected: past
// Stripe's idempotency retention a replay mints a genuinely new payable
// session, and the stock behind the old one is already going back. The member
// gets a fresh order; the abandoned one releases its hold.
func TestStaleOrderIsAbandonedRatherThanResumed(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	seedTier(t, pool, "hotspot-device", "device", false)
	cleanupOrders(t, pool, person.UserID)

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = ""
	if _, err := svc.StartEnrollment(ctx, person, req); err != nil {
		t.Fatalf("first StartEnrollment: %v", err)
	}
	// Well past the resume window.
	svc.SetClockForTest(func() time.Time { return time.Now().Add(30 * time.Hour) })
	if _, err := svc.StartEnrollment(ctx, person, req); err != nil {
		t.Fatalf("StartEnrollment after the window: %v", err)
	}

	var expired, pending int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'expired'),
		       count(*) FILTER (WHERE state = 'checkout_pending')
		FROM orders WHERE user_id = $1
	`, person.UserID).Scan(&expired, &pending); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if expired != 1 || pending != 1 {
		t.Errorf("orders: %d expired, %d pending; want 1 and 1 — the stale one abandoned, a fresh one created", expired, pending)
	}
}

// Two submissions racing past the pending-order check: the loser must be
// handed the winner's Checkout page, not a 500.
func TestConcurrentSubmissionsResumeTheWinner(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	cleanupOrders(t, pool, person.UserID)

	const attempts = 4
	urls := make([]string, attempts)
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			urls[i], errs[i] = svc.StartEnrollment(ctx, person, enrollment(tier.Slug))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("attempt %d failed: %v", i, err)
		}
	}
	for i := 1; i < attempts; i++ {
		if urls[i] != urls[0] {
			t.Errorf("attempt %d got %q, attempt 0 got %q: a double-click must land on one page", i, urls[i], urls[0])
		}
	}
	var orders int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE user_id = $1`, person.UserID).Scan(&orders); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if orders != 1 {
		t.Errorf("%d orders, want exactly 1", orders)
	}
	if fake.SessionCount() != 1 {
		t.Errorf("%d sessions, want exactly 1", fake.SessionCount())
	}
}

// The window a review found: a stale order whose session was paid before the
// portal got around to abandoning it.
//
// Stripe refuses to expire a completed session, and the whole safety argument
// rests on that refusal — so it is worth proving rather than asserting. The
// abandonment must fail and the order must stay exactly as it is: the money has
// arrived and the projector settles it on the next pass. Abandoning it would
// move a paid order to expired, and the projector would then find money against
// an unpayable order and page a human for nothing.
func TestStaleOrderPaidBeforeAbandonmentIsLeftAlone(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true)
	seedTier(t, pool, "hotspot-device", "device", false)
	cleanupOrders(t, pool, person.UserID)

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = ""
	if _, err := svc.StartEnrollment(ctx, person, req); err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	var sessionID string
	if err := pool.Conn().QueryRow(ctx,
		`SELECT stripe_checkout_session_id FROM orders WHERE user_id = $1`,
		person.UserID).Scan(&sessionID); err != nil {
		t.Fatalf("read session: %v", err)
	}

	// The member pays, then comes back after the resume window.
	fake.SettleSession(sessionID, "pi_late1", "")
	svc.SetClockForTest(func() time.Time { return time.Now().Add(30 * time.Hour) })

	if _, err := svc.StartEnrollment(ctx, person, req); err == nil {
		t.Fatal("a paid session was abandoned; the projector would then find money against an expired order")
	}

	// The order is untouched — the projector's job now.
	var state string
	if err := pool.Conn().QueryRow(ctx,
		`SELECT state FROM orders WHERE user_id = $1`, person.UserID).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "checkout_pending" {
		t.Errorf("order state = %s, want checkout_pending awaiting settlement", state)
	}
	// And exactly one order survives: the failed abandonment must not have
	// created a second while leaving the first payable.
	var count int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE user_id = $1`, person.UserID).Scan(&count); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if count != 1 {
		t.Errorf("%d orders, want 1", count)
	}
}
