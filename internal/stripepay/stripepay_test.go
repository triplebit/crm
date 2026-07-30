package stripepay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"triplebit.org/portal/internal/core"
)

const (
	membershipsAcct = "acct_memberships1"
	donationsAcct   = "acct_donations1"
)

// fakeStripe records every request and serves canned Stripe-shaped JSON. It
// asserts nothing itself; tests inspect what it captured.
type fakeStripe struct {
	server   *httptest.Server
	requests []capturedRequest

	// respond overrides the default responses when set.
	respond func(w http.ResponseWriter, r *http.Request) bool
}

type capturedRequest struct {
	Method         string
	Path           string
	StripeContext  string
	IdempotencyKey string
	Body           string
}

func newFakeStripe(t *testing.T) *fakeStripe {
	t.Helper()
	f := &fakeStripe{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<16)
		n, _ := r.Body.Read(body)
		f.requests = append(f.requests, capturedRequest{
			Method:         r.Method,
			Path:           r.URL.Path,
			StripeContext:  r.Header.Get("Stripe-Context"),
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
			Body:           string(body[:n]),
		})
		if f.respond != nil && f.respond(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/products"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "prod_test1", "object": "product", "name": "Hotspot Basic", "active": true,
			})
		case strings.HasPrefix(r.URL.Path, "/v1/prices"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "price_test1", "object": "price", "product": "prod_test1",
				"unit_amount": 1500, "currency": "usd", "active": true,
				"recurring": map[string]any{"interval": "month", "interval_count": 1},
			})
		default:
			http.Error(w, `{"error":{"message":"unexpected path"}}`, http.StatusBadRequest)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func newTestClient(t *testing.T, f *fakeStripe) *Client {
	t.Helper()
	c, err := New(Options{
		APIKey:               "sk_test_abc",
		Environment:          core.StripeSandbox,
		MembershipsAccountID: membershipsAcct,
		DonationsAccountID:   donationsAcct,
		BaseURL:              f.server.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func (f *fakeStripe) last(t *testing.T) capturedRequest {
	t.Helper()
	if len(f.requests) == 0 {
		t.Fatal("no request reached the fake Stripe server")
	}
	return f.requests[len(f.requests)-1]
}

func TestEveryCallCarriesTheAccountContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeStripe(t)
	c := newTestClient(t, f)

	if _, err := c.CreateProduct(ctx, core.Memberships, "idem-1", ProductSpec{Name: "Hotspot Basic", Slug: "hotspot-basic"}); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}
	if got := f.last(t).StripeContext; got != membershipsAcct {
		t.Errorf("Stripe-Context = %q, want %q", got, membershipsAcct)
	}

	if _, err := c.GetPrice(ctx, core.Donations, "price_test1"); err != nil {
		t.Fatalf("GetPrice: %v", err)
	}
	if got := f.last(t).StripeContext; got != donationsAcct {
		t.Errorf("Stripe-Context = %q, want %q", got, donationsAcct)
	}
}

// Hazard 2: a mutating call without an explicit idempotency key must be
// refused locally — if it reached the library, a random key would be minted
// and a crash-retry would duplicate the mutation.
func TestMutationsRequireAnExplicitIdempotencyKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeStripe(t)
	c := newTestClient(t, f)

	if _, err := c.CreateProduct(ctx, core.Memberships, "", ProductSpec{Name: "X", Slug: "x"}); err == nil {
		t.Error("CreateProduct without an idempotency key was accepted")
	}
	if _, err := c.CreatePrice(ctx, core.Memberships, "  ", PriceSpec{ProductID: "prod_1", Currency: "usd", UnitAmount: 100}); err == nil {
		t.Error("CreatePrice with a blank idempotency key was accepted")
	}
	if _, err := c.DeactivatePrice(ctx, core.Memberships, "", "price_1"); err == nil {
		t.Error("DeactivatePrice without an idempotency key was accepted")
	}
	if len(f.requests) != 0 {
		t.Fatalf("%d requests reached Stripe despite missing idempotency keys; the refusal must be local", len(f.requests))
	}

	// And when supplied, the key must actually arrive as the header.
	if _, err := c.CreateProduct(ctx, core.Memberships, "idem-42", ProductSpec{Name: "X", Slug: "x"}); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}
	if got := f.last(t).IdempotencyKey; got != "idem-42" {
		t.Errorf("Idempotency-Key header = %q, want %q", got, "idem-42")
	}
}

// Hazard 1: a response past the cap must fail the call, not balloon memory.
func TestOversizedResponsesAreRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeStripe(t)
	f.respond = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"prod_big","object":"product","name":"`))
		filler := strings.Repeat("x", 64<<10)
		for written := 0; written < 3<<20; written += len(filler) {
			_, _ = w.Write([]byte(filler))
		}
		_, _ = w.Write([]byte(`","active":true}`))
		return true
	}

	c, err := New(Options{
		APIKey:               "sk_test_abc",
		Environment:          core.StripeSandbox,
		MembershipsAccountID: membershipsAcct,
		DonationsAccountID:   donationsAcct,
		BaseURL:              f.server.URL,
		MaxResponseBytes:     1 << 20,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetProduct(ctx, core.Memberships, "prod_big"); err == nil {
		t.Fatal("a 3 MiB response passed a 1 MiB cap")
	} else if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error %v does not mention the cap", err)
	}
}

func TestPriceRoundTripAndDeactivation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeStripe(t)
	c := newTestClient(t, f)

	price, err := c.CreatePrice(ctx, core.Memberships, "idem-p1", PriceSpec{
		ProductID: "prod_test1", Slug: "hotspot-basic",
		UnitAmount: 1500, Currency: "usd",
		Recurring: true, Interval: "month",
	})
	if err != nil {
		t.Fatalf("CreatePrice: %v", err)
	}
	if price.ID != "price_test1" || price.ProductID != "prod_test1" ||
		price.UnitAmount != 1500 || !price.Recurring || price.Interval != "month" {
		t.Errorf("price mapped wrong: %+v", price)
	}
	body := f.last(t).Body
	for _, want := range []string{"unit_amount=1500", "currency=usd", "recurring[interval]=month", "product=prod_test1"} {
		if !strings.Contains(body, want) {
			t.Errorf("create body %q is missing %q", body, want)
		}
	}

	if _, err := c.DeactivatePrice(ctx, core.Memberships, "idem-p2", "price_test1"); err != nil {
		t.Fatalf("DeactivatePrice: %v", err)
	}
	if body := f.last(t).Body; !strings.Contains(body, "active=false") {
		t.Errorf("deactivate body %q does not set active=false", body)
	}
}

func TestSpecValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeStripe(t)
	c := newTestClient(t, f)

	cases := map[string]PriceSpec{
		"no product":                 {Currency: "usd", UnitAmount: 100},
		"no currency":                {ProductID: "prod_1", UnitAmount: 100},
		"negative amount":            {ProductID: "prod_1", Currency: "usd", UnitAmount: -1},
		"recurring without interval": {ProductID: "prod_1", Currency: "usd", UnitAmount: 100, Recurring: true},
		"one-time with interval":     {ProductID: "prod_1", Currency: "usd", UnitAmount: 100, Interval: "month"},
	}
	for name, spec := range cases {
		if _, err := c.CreatePrice(ctx, core.Memberships, "idem", spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.requests) != 0 {
		t.Fatalf("%d invalid specs reached Stripe", len(f.requests))
	}
}

// Hazard 3's cousin at construction time: a key whose mode disagrees with the
// environment must never build a client.
func TestKeyModeMustMatchEnvironment(t *testing.T) {
	t.Parallel()
	base := Options{
		MembershipsAccountID: membershipsAcct,
		DonationsAccountID:   donationsAcct,
	}

	live := base
	live.APIKey, live.Environment = "sk_live_abc", core.StripeSandbox
	if _, err := New(live); err == nil {
		t.Error("a live key was accepted outside production")
	}

	test := base
	test.APIKey, test.Environment = "sk_test_abc", core.StripeProduction
	if _, err := New(test); err == nil {
		t.Error("a test key was accepted in production")
	}

	junk := base
	junk.APIKey, junk.Environment = "not-a-key", core.StripeSandbox
	if _, err := New(junk); err == nil {
		t.Error("a malformed key was accepted")
	}

	same := base
	same.APIKey, same.Environment = "sk_test_abc", core.StripeSandbox
	same.DonationsAccountID = membershipsAcct
	if _, err := New(same); err == nil {
		t.Error("the same account ID was accepted for both accounts")
	}
}
