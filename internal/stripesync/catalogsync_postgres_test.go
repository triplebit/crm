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
// syncer builds on) and remembers created objects so retrieval works.
type fakeStripe struct {
	mu       sync.Mutex
	server   *httptest.Server
	byIdem   map[string]map[string]any
	prices   map[string]map[string]any
	products map[string]map[string]any
	seq      int

	creates int // POSTs that created something new (not idempotent replays)
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
		}
		f.products[obj["id"].(string)] = obj
		f.byIdem[idem] = obj
		f.creates++
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
			obj["active"] = false
		}
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
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

func newSyncer(t *testing.T, f *fakeStripe) (*Syncer, *db.Pool) {
	t.Helper()
	pool := testdb.Pool(t)
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

// manifest builds a one-item manifest with a unique slug per test, so tests
// stay independent in the shared database.
func manifest(t *testing.T, dollars string) (catalog.Manifest, string) {
	t.Helper()
	slug := "sync-tier-" + uuid.New().String()[:8]
	m, err := catalog.Parse(strings.NewReader(fmt.Sprintf(`{
	  "items": [{
	    "slug": %q, "name": "Sync Tier", "kind": "hotspot_tier",
	    "price": {"amount": %q, "currency": "usd", "recurring": true, "interval": "month"}
	  }]
	}`, slug, dollars)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m, slug
}

func cleanupItem(t *testing.T, pool *db.Pool, slug string) {
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Conn().Exec(ctx,
			`DELETE FROM catalog_price_versions WHERE catalog_item_id IN (SELECT id FROM catalog_items WHERE slug = $1)`, slug)
		_, _ = pool.Conn().Exec(ctx, `DELETE FROM catalog_items WHERE slug = $1`, slug)
	})
}

func TestFreshSyncCreatesAndVerifies(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	m, slug := manifest(t, "15.00")
	cleanupItem(t, pool, slug)

	result, err := s.Sync(ctx, m)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("result = %s, want 1 created", result)
	}

	var amount int64
	var verified *string
	var priceID string
	err = pool.Conn().QueryRow(ctx, `
		SELECT v.amount, v.verified_at::text, v.stripe_price_id
		FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE i.slug = $1 AND v.active_until IS NULL
	`, slug).Scan(&amount, &verified, &priceID)
	if err != nil {
		t.Fatalf("read version back: %v", err)
	}
	if amount != 1500 {
		t.Errorf("amount = %d, want 1500", amount)
	}
	if verified == nil {
		t.Error("the fresh version was not verified against Stripe")
	}
	if !f.priceActive(priceID) {
		t.Error("the recorded price is not active in Stripe")
	}
}

// The same manifest twice: the second run must change nothing and call no
// mutating Stripe endpoint — that is what makes sync safe to run from cron.
func TestResyncOfUnchangedManifestIsANoOp(t *testing.T) {
	ctx := context.Background()
	f := newFakeStripe(t)
	s, pool := newSyncer(t, f)
	m, slug := manifest(t, "15.00")
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, m); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	createsAfterFirst := f.creates

	result, err := s.Sync(ctx, m)
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if result.Unchanged != 1 || result.Created != 0 || result.Rotated != 0 {
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
	m, slug := manifest(t, "15.00")
	cleanupItem(t, pool, slug)

	if _, err := s.Sync(ctx, m); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	var oldPriceID string
	if err := pool.Conn().QueryRow(ctx, `
		SELECT v.stripe_price_id FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE i.slug = $1 AND v.active_until IS NULL
	`, slug).Scan(&oldPriceID); err != nil {
		t.Fatalf("read old version: %v", err)
	}

	changed, err := catalog.Parse(strings.NewReader(fmt.Sprintf(
		`{"items": [{"slug": %q, "name": "Sync Tier", "kind": "hotspot_tier",
		 "price": {"amount": "20.00", "currency": "usd", "recurring": true, "interval": "month"}}]}`, slug)))
	if err != nil {
		t.Fatalf("Parse changed manifest: %v", err)
	}

	result, err := s.Sync(ctx, changed)
	if err != nil {
		t.Fatalf("Sync after change: %v", err)
	}
	if result.Rotated != 1 {
		t.Errorf("result = %s, want 1 rotated", result)
	}

	// History: exactly one closed version at the old amount, one open and
	// verified at the new amount, and the old price retired in Stripe.
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
	var newAmount int64
	if err := pool.Conn().QueryRow(ctx, `
		SELECT v.amount FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE i.slug = $1 AND v.active_until IS NULL
	`, slug).Scan(&newAmount); err != nil {
		t.Fatalf("read new version: %v", err)
	}
	if newAmount != 2000 {
		t.Errorf("open version amount = %d, want 2000", newAmount)
	}
	if f.priceActive(oldPriceID) {
		t.Error("the replaced price is still active in Stripe")
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
