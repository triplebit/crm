package stripesync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/catalog"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/testdb"
)

// fakeStripe is stateful where it matters for sync: it honours idempotency
// keys (same key → same object, which is the crash-recovery contract the
// syncer builds on), remembers created objects so retrieval works, and can
// fail a chosen call once to simulate a crash mid-sequence.
type fakeStripe struct {
	mu       sync.Mutex
	server   *httptest.Server
	byIdem   map[string]map[string]any
	prices   map[string]map[string]any
	products map[string]map[string]any
	seq      int

	creates     int // POSTs that created something new (not idempotent replays)
	priceGets   int
	productGets int

	// failDeactivations makes that many price-deactivation calls fail with a
	// 500 before behaving again, for crash-injection tests.
	failDeactivations int
}

func newFakeStripe(t *testing.T) *fakeStripe {
	t.Helper()
	f := &fakeStripe{
		byIdem:   map[string]map[string]any{},
		prices:   map[string]map[string]any{},
		products: map[string]map[string]any{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeStripe) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = r.ParseForm()

	respond := func(obj map[string]any) { _ = json.NewEncoder(w).Encode(obj) }

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/products":
		idem := r.Header.Get("Idempotency-Key")
		if prior, ok := f.byIdem[idem]; ok {
			respond(prior)
			return
		}
		f.seq++
		obj := map[string]any{
			"id": fmt.Sprintf("prod_%d", f.seq), "object": "product",
			"name": r.PostForm.Get("name"), "active": true,
			"metadata": map[string]any{"portal_slug": r.PostForm.Get("metadata[portal_slug]")},
		}
		f.products[obj["id"].(string)] = obj
		f.byIdem[idem] = obj
		f.creates++
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/products/"):
		f.productGets++
		id := strings.TrimPrefix(r.URL.Path, "/v1/products/")
		if obj, ok := f.products[id]; ok {
			respond(obj)
			return
		}
		http.Error(w, `{"error":{"message":"no such product"}}`, http.StatusNotFound)

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/products/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/products/")
		obj, ok := f.products[id]
		if !ok {
			http.Error(w, `{"error":{"message":"no such product"}}`, http.StatusNotFound)
			return
		}
		if name := r.PostForm.Get("name"); name != "" {
			obj["name"] = name
		}
		respond(obj)

	case r.Method == http.MethodPost && r.URL.Path == "/v1/prices":
		idem := r.Header.Get("Idempotency-Key")
		if prior, ok := f.byIdem[idem]; ok {
			respond(prior)
			return
		}
		f.seq++
		obj := map[string]any{
			"id": fmt.Sprintf("price_%d", f.seq), "object": "price",
			"product":  r.PostForm.Get("product"),
			"currency": r.PostForm.Get("currency"),
			"active":   true,
		}
		var amount int64
		_, _ = fmt.Sscan(r.PostForm.Get("unit_amount"), &amount)
		obj["unit_amount"] = amount
		if interval := r.PostForm.Get("recurring[interval]"); interval != "" {
			var count int64 = 1
			_, _ = fmt.Sscan(r.PostForm.Get("recurring[interval_count]"), &count)
			obj["recurring"] = map[string]any{"interval": interval, "interval_count": count}
		}
		f.prices[obj["id"].(string)] = obj
		f.byIdem[idem] = obj
		f.creates++
		respond(obj)

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
		obj, ok := f.prices[id]
		if !ok {
			http.Error(w, `{"error":{"message":"no such price"}}`, http.StatusNotFound)
			return
		}
		if r.PostForm.Get("active") == "false" {
			if f.failDeactivations > 0 {
				f.failDeactivations--
				http.Error(w, `{"error":{"message":"injected failure"}}`, http.StatusInternalServerError)
				return
			}
			obj["active"] = false
		}
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		f.priceGets++
		id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
		if obj, ok := f.prices[id]; ok {
			respond(obj)
			return
		}
		http.Error(w, `{"error":{"message":"no such price"}}`, http.StatusNotFound)

	default:
		http.Error(w, `{"error":{"message":"unexpected `+r.Method+` `+r.URL.Path+`"}}`, http.StatusBadRequest)
	}
}

func (f *fakeStripe) priceActive(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.prices[id]
	return ok && obj["active"] == true
}

func (f *fakeStripe) productName(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if obj, ok := f.products[id]; ok {
		return obj["name"].(string)
	}
	return ""
}

// activePriceCount reports how many of the fake's prices are still active —
// the orphan detector for the concurrency test.
func (f *fakeStripe) activePriceCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.prices {
		if p["active"] == true {
			n++
		}
	}
	return n
}

func newSyncer(t *testing.T, f *fakeStripe) (*Syncer, *db.Pool) {
	t.Helper()
	pool := testdb.Pool(t)

	// The retirement pass sees every open version in the environment, so a
	// leaked row from a crashed earlier run — referencing a price only that
	// run's fake knew — would fail the first sync of this run. Sweep our own
	// namespace up front; the flaky-schema-test incident taught exactly this.
	ctx := context.Background()
	_, _ = pool.Conn().Exec(ctx,
		`DELETE FROM catalog_price_versions WHERE catalog_item_id IN (SELECT id FROM catalog_items WHERE slug LIKE 'sync-%')`)
	_, _ = pool.Conn().Exec(ctx, `DELETE FROM catalog_items WHERE slug LIKE 'sync-%'`)

	pay, err := stripepay.New(stripepay.Options{
		APIKey:               "sk_test_sync",
		Environment:          core.StripeSandbox,
		MembershipsAccountID: "acct_m1",
		DonationsAccountID:   "acct_d1",
		BaseURL:              f.server.URL,
	})
	if err != nil {
		t.Fatalf("stripepay.New: %v", err)
	}
	s, err := New(Options{
		Repo: catalogdb.New(), Pool: pool, Pay: pay,
		Environment: core.StripeSandbox,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, pool
}

// itemJSON renders one manifest entry.
func itemJSON(slug, name, kind, dollars string) string {
	recurring := `"recurring": true, "interval": "month"`
	if kind == "device" || kind == "donation" {
		recurring = `"recurring": false`
	}
	return fmt.Sprintf(`{"slug": %q, "name": %q, "kind": %q,
	  "price": {"amount": %q, "currency": "usd", %s}}`, slug, name, kind, dollars, recurring)
}

func parseManifest(t *testing.T, items ...string) catalog.Manifest {
	t.Helper()
	m, err := catalog.Parse(strings.NewReader(`{"items": [` + strings.Join(items, ",") + `]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func slugFor(t *testing.T) string {
	t.Helper()
	return "sync-" + uuid.New().String()[:8]
}

func cleanupItem(t *testing.T, pool *db.Pool, slug string) {
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Conn().Exec(ctx,
			`DELETE FROM catalog_price_versions WHERE catalog_item_id IN (SELECT id FROM catalog_items WHERE slug = $1)`, slug)
		_, _ = pool.Conn().Exec(ctx, `DELETE FROM catalog_items WHERE slug = $1`, slug)
	})
}

// openVersion reads the single open version for a slug, failing if there is
// not exactly one.
func openVersion(t *testing.T, pool *db.Pool, slug string) (priceID, productID, account string, amount int64, verified bool) {
	t.Helper()
	err := pool.Conn().QueryRow(context.Background(), `
		SELECT v.stripe_price_id, v.stripe_product_id, v.account_ref, v.amount,
		       v.verified_at IS NOT NULL
		FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE i.slug = $1 AND v.active_until IS NULL
	`, slug).Scan(&priceID, &productID, &account, &amount, &verified)
	if err != nil {
		t.Fatalf("read open version for %s: %v", slug, err)
	}
	return
}

func TestFreshSyncCreatesAndVerifiesByReadingBack(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	result, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "15.00")))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("result = %s, want 1 created", result)
	}

	priceID, _, _, amount, verified := openVersion(t, pool, slug)
	if amount != 1500 {
		t.Errorf("amount = %d, want 1500", amount)
	}
	if !verified {
		t.Error("the fresh version was not verified")
	}
	if !f.priceActive(priceID) {
		t.Error("the recorded price is not active in Stripe")
	}
	// verified_at must have been EARNED: the create path performs an
	// independent price retrieve and a product retrieve. A create response
	// alone must never set it.
	if f.priceGets < 1 || f.productGets < 1 {
		t.Errorf("verification read back %d prices and %d products; both must be at least 1",
			f.priceGets, f.productGets)
	}
}

// The same manifest twice: the second run must change nothing and call no
// mutating Stripe endpoint — that is what makes sync safe to run from cron.
func TestResyncOfUnchangedManifestIsANoOp(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)
	m := parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "15.00"))

	if _, err := s.Sync(ctx, m); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	createsAfterFirst := f.creates

	result, err := s.Sync(ctx, m)
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if result.Unchanged != 1 || result.Created != 0 || result.Rotated != 0 || result.Retired != 0 {
		t.Errorf("second sync result = %s, want 1 unchanged", result)
	}
	if f.creates != createsAfterFirst {
		t.Errorf("second sync created %d new Stripe objects; an unchanged manifest must create none", f.creates-createsAfterFirst)
	}
}

func TestPriceChangeRotatesTheVersion(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "15.00"))); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	oldPriceID, _, _, _, _ := openVersion(t, pool, slug)

	result, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "20.00")))
	if err != nil {
		t.Fatalf("Sync after change: %v", err)
	}
	if result.Rotated != 1 {
		t.Errorf("result = %s, want 1 rotated", result)
	}

	var open, closed int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE active_until IS NULL),
		       count(*) FILTER (WHERE active_until IS NOT NULL)
		FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE i.slug = $1
	`, slug).Scan(&open, &closed); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if open != 1 || closed != 1 {
		t.Errorf("version history: %d open, %d closed; want 1 and 1 — history is never edited, only extended", open, closed)
	}
	_, _, _, newAmount, verified := openVersion(t, pool, slug)
	if newAmount != 2000 || !verified {
		t.Errorf("open version amount = %d verified = %t, want 2000 and true", newAmount, verified)
	}
	if f.priceActive(oldPriceID) {
		t.Error("the replaced price is still active in Stripe")
	}
}

// B-1: absence retires. A slug deleted from the manifest stops being
// sellable — locally and in Stripe — and the item records that it used to be.
func TestRemovedItemIsRetired(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	removed, kept := slugFor(t), slugFor(t)
	cleanupItem(t, pool, removed)
	cleanupItem(t, pool, kept)

	if _, err := s.Sync(ctx, parseManifest(t,
		itemJSON(removed, "Doomed Tier", "hotspot_tier", "15.00"),
		itemJSON(kept, "Kept Tier", "hotspot_tier", "10.00"))); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	removedPriceID, _, _, _, _ := openVersion(t, pool, removed)

	result, err := s.Sync(ctx, parseManifest(t, itemJSON(kept, "Kept Tier", "hotspot_tier", "10.00")))
	if err != nil {
		t.Fatalf("Sync without %s: %v", removed, err)
	}
	if result.Retired != 1 || result.Unchanged != 1 {
		t.Errorf("result = %s, want 1 retired and 1 unchanged", result)
	}

	var active bool
	var openCount int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT i.active, count(v.id) FILTER (WHERE v.active_until IS NULL)
		FROM catalog_items i
		LEFT JOIN catalog_price_versions v ON v.catalog_item_id = i.id
		WHERE i.slug = $1
		GROUP BY i.active
	`, removed).Scan(&active, &openCount); err != nil {
		t.Fatalf("read removed item: %v", err)
	}
	if active {
		t.Error("the removed item is still sellable locally")
	}
	if openCount != 0 {
		t.Errorf("%d open versions survived retirement", openCount)
	}
	if f.priceActive(removedPriceID) {
		t.Error("the removed item's price is still active in Stripe")
	}

	// Retirement is not deletion: the history remains.
	var history int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id WHERE i.slug = $1
	`, removed).Scan(&history); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if history != 1 {
		t.Errorf("history rows = %d, want 1: retirement must not erase what was sellable", history)
	}
}

// B-1's second face: a kind change moves an item between accounts. The new
// context gets a version; the old context's version closes and its price
// retires. Nothing stays sellable in an account the manifest no longer
// routes it to.
func TestKindChangeMovesTheItemBetweenAccounts(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Mover", "hotspot_tier", "15.00"))); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	oldPriceID, _, oldAccount, _, _ := openVersion(t, pool, slug)
	if oldAccount != "memberships" {
		t.Fatalf("hotspot tier landed in %q", oldAccount)
	}

	result, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Mover", "friends_tier", "15.00")))
	if err != nil {
		t.Fatalf("Sync after kind change: %v", err)
	}
	if result.Created != 1 || result.Retired != 1 {
		t.Errorf("result = %s, want 1 created and 1 retired", result)
	}
	_, _, newAccount, _, verified := openVersion(t, pool, slug)
	if newAccount != "donations" || !verified {
		t.Errorf("open version account = %q verified = %t, want donations and true", newAccount, verified)
	}
	if f.priceActive(oldPriceID) {
		t.Error("the old account's price is still active in Stripe")
	}
}

// S-1: a rename converges on the next sync, without a price rotation.
func TestProductRenameConverges(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Old Name", "hotspot_tier", "15.00"))); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	_, productID, _, _, _ := openVersion(t, pool, slug)

	result, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "New Name", "hotspot_tier", "15.00")))
	if err != nil {
		t.Fatalf("Sync after rename: %v", err)
	}
	if result.Renamed != 1 || result.Rotated != 0 {
		t.Errorf("result = %s, want 1 renamed and 0 rotated", result)
	}
	if got := f.productName(productID); got != "New Name" {
		t.Errorf("Stripe product name = %q, want %q", got, "New Name")
	}
}

// A sync that dies between creating the successor and recording it must
// converge on the next run without minting a second successor.
func TestFailedRotationConvergesOnRerun(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "15.00"))); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	changed := parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "20.00"))

	// The successor is created, then the old price's deactivation fails:
	// the sync dies after the remote create, before anything was recorded.
	f.failDeactivations = 1
	if _, err := s.Sync(ctx, changed); err == nil {
		t.Fatal("the injected deactivation failure did not surface")
	}
	pricesAfterCrash := f.creates

	result, err := s.Sync(ctx, changed)
	if err != nil {
		t.Fatalf("re-run after crash: %v", err)
	}
	if result.Rotated != 1 {
		t.Errorf("re-run result = %s, want 1 rotated", result)
	}
	if f.creates != pricesAfterCrash {
		t.Errorf("the re-run created %d new Stripe objects; the idempotency key must replay the crashed successor",
			f.creates-pricesAfterCrash)
	}
	_, _, _, amount, verified := openVersion(t, pool, slug)
	if amount != 2000 || !verified {
		t.Errorf("converged version amount = %d verified = %t, want 2000 and true", amount, verified)
	}
}

// S-2: two concurrent syncs with different desired prices must serialise on
// the advisory lock. The end state is one open version whose price is active
// in Stripe, the other superseded — never an orphan active price.
func TestConcurrentSyncsCannotOrphanAPrice(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	slug := slugFor(t)
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "10.00"))); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}

	a := parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "20.00"))
	b := parseManifest(t, itemJSON(slug, "Sync Tier", "hotspot_tier", "30.00"))
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = s.Sync(ctx, a) }()
	go func() { defer wg.Done(); _, errs[1] = s.Sync(ctx, b) }()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent sync %d failed: %v", i, err)
		}
	}

	priceID, _, _, amount, _ := openVersion(t, pool, slug) // fails if not exactly one open
	if amount != 2000 && amount != 3000 {
		t.Errorf("final amount = %d, want one of the two competing manifests", amount)
	}
	if !f.priceActive(priceID) {
		t.Error("the surviving version's price is not active in Stripe")
	}
	if got := f.activePriceCount(); got != 1 {
		t.Errorf("%d active prices in Stripe, want exactly 1: an extra one is an orphan no local row references", got)
	}
}

// The idempotency key is the crash-recovery mechanism: the same manifest
// against the same predecessor must produce the same key, and a different
// predecessor (A→B→A) must not.
func TestPriceIdempotencyKeyIsDeterministicAndPredecessorBound(t *testing.T) {
	t.Parallel()
	spec := catalog.PriceSpec{Amount: 1500, Currency: "usd", Recurring: true, Interval: "month", IntervalCount: 1}

	a := priceIdempotencyKey(core.StripeSandbox, "tier", spec, "price_1")
	b := priceIdempotencyKey(core.StripeSandbox, "tier", spec, "price_1")
	if a != b {
		t.Error("the same spec and predecessor produced different keys; a crashed sync would duplicate the price")
	}
	if priceIdempotencyKey(core.StripeSandbox, "tier", spec, "price_2") == a {
		t.Error("a different predecessor produced the same key; A→B→A inside the idempotency window would replay the stale price")
	}
	spec.Amount = 2000
	if priceIdempotencyKey(core.StripeSandbox, "tier", spec, "price_1") == a {
		t.Error("a different amount produced the same key")
	}
}
