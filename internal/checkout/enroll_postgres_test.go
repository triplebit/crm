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

// seedTier inserts an active catalog item with a verified open price version
// and, when stocked >= 0, an inventory row. Slugs are unique per test; the
// device add-on uses the fixed slug the service resolves.
func seedTier(t *testing.T, pool *db.Pool, slug, kind string, recurring bool, stocked int) catalogdb.Item {
	t.Helper()
	ctx := context.Background()
	repo := catalogdb.New()

	// Self-healing: a crashed earlier run may have leaked this slug's rows,
	// and the open-version unique index would refuse the seed. Deleting is
	// fragile (leaked orders hold foreign keys into the catalog), so leaked
	// open versions are closed instead — harmless history — and the
	// inventory seed below is an upsert. Never trust the previous run's
	// cleanup.
	_, _ = pool.Conn().Exec(ctx, `
		UPDATE catalog_price_versions SET active_until = now()
		WHERE active_until IS NULL
		  AND catalog_item_id IN (SELECT id FROM catalog_items WHERE slug = $1)
	`, slug)

	item, err := repo.UpsertItem(ctx, pool.Conn(), catalogdb.Item{
		Slug: slug, Name: "Test " + slug, Kind: kind,
		Program:          "hotspot",
		RequiresShipping: true, RequiresIMEI: true, InventoryTracked: stocked >= 0,
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
	if stocked >= 0 {
		if _, err := pool.Conn().Exec(ctx, `
			INSERT INTO inventory (id, catalog_item_id, variant, on_hand, reserved, safety_stock)
			VALUES ($1, $2, 'default', $3, 0, 0)
			ON CONFLICT (catalog_item_id, variant)
				DO UPDATE SET on_hand = EXCLUDED.on_hand, reserved = 0
		`, uuid.New(), item.ID, stocked); err != nil {
			t.Fatalf("seed inventory %s: %v", slug, err)
		}
	}

	t.Cleanup(func() {
		c := context.Background()
		// Close rather than delete, for the same foreign-key reason as the
		// upfront sweep; the next run's sweep handles the rest.
		_, _ = pool.Conn().Exec(c, `
			UPDATE catalog_price_versions SET active_until = now()
			WHERE active_until IS NULL AND catalog_item_id = $1
		`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM inventory_reservations WHERE inventory_id IN (SELECT id FROM inventory WHERE catalog_item_id = $1)`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM inventory WHERE catalog_item_id = $1`, item.ID)
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
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
	seedTier(t, pool, "hotspot-device", "device", false, 3)
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

	var lines, reservations int
	var lineAmountSum int64
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*), COALESCE(sum(amount), 0) FROM order_lines WHERE order_id = $1
	`, orderID).Scan(&lines, &lineAmountSum); err != nil {
		t.Fatalf("count lines: %v", err)
	}
	if lines != 2 || lineAmountSum != 15000 {
		t.Errorf("lines=%d sum=%d; want 2 lines totalling 15000", lines, lineAmountSum)
	}
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM inventory_reservations r
		JOIN order_lines l ON l.id = r.order_line_id
		WHERE l.order_id = $1 AND r.state = 'held'
	`, orderID).Scan(&reservations); err != nil {
		t.Fatalf("count reservations: %v", err)
	}
	if reservations != 1 {
		t.Errorf("%d held reservations, want 1 (the device; the tier is stockless in this test)", reservations)
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

// Overselling rolls back everything: the schema's reserved <= on_hand check
// fails the reservation, and with it the order and its lines.
func TestStartEnrollmentRefusesWhenOutOfStock(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
	seedTier(t, pool, "hotspot-device", "device", false, 0) // none on hand
	cleanupOrders(t, pool, person.UserID)

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = ""
	_, err := svc.StartEnrollment(ctx, person, req)
	if err == nil {
		t.Fatal("an out-of-stock device was sold")
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
		t.Errorf("%d order rows survived the rollback", orphans)
	}
	if fake.SessionCount() != 0 {
		t.Error("a checkout session was created for a failed order")
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
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
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
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
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
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
	device := seedTier(t, pool, "hotspot-device", "device", false, 5)
	cleanupOrders(t, pool, person.UserID)

	req := enrollment(tier.Slug)
	req.IncludeDevice = true
	req.IMEI = ""
	if _, err := svc.StartEnrollment(ctx, person, req); err != nil {
		t.Fatalf("first StartEnrollment: %v", err)
	}
	reservedBefore := reservedCount(t, pool, device.ID)
	if reservedBefore != 1 {
		t.Fatalf("reserved = %d after enrolling, want 1", reservedBefore)
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
	// The abandoned order's hold went back, and the new order took its own.
	if got := reservedCount(t, pool, device.ID); got != 1 {
		t.Errorf("reserved = %d, want 1: the stale hold must be released as the new one is taken", got)
	}
	var released int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM inventory_reservations r
		JOIN order_lines l ON l.id = r.order_line_id
		JOIN orders o ON o.id = l.order_id
		WHERE o.user_id = $1 AND r.state = 'released'
	`, person.UserID).Scan(&released); err != nil {
		t.Fatalf("count released: %v", err)
	}
	if released != 1 {
		t.Errorf("%d released reservations, want 1", released)
	}
}

// Two submissions racing past the pending-order check: the loser must be
// handed the winner's Checkout page, not a 500.
func TestConcurrentSubmissionsResumeTheWinner(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedTier(t, pool, "tier-"+uuid.New().String()[:8], "hotspot_tier", true, -1)
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

func reservedCount(t *testing.T, pool *db.Pool, itemID uuid.UUID) int {
	t.Helper()
	var reserved int
	if err := pool.Conn().QueryRow(context.Background(),
		`SELECT reserved FROM inventory WHERE catalog_item_id = $1`, itemID).Scan(&reserved); err != nil {
		t.Fatalf("read reserved: %v", err)
	}
	return reserved
}
