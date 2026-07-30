// Package stripetest is the fake Stripe server the portal's tests share. It
// is stateful where the production code's correctness arguments are stateful:
//
//   - Idempotency keys replay: the same key returns the same object without
//     creating another, which is the crash-recovery contract every syncer
//     and checkout path builds on.
//   - Customers propagate: a Customer created under one account's
//     Stripe-Context becomes visible under the sibling's only after a
//     configurable number of reads, imitating Organization customer sharing
//     lag (measured ~1.1s in the real sandbox; expressed here in reads, not
//     time, so tests stay instant).
//   - Failures inject: a chosen number of upcoming price deactivations or
//     customer creations can be made to fail, for crash-window tests.
//
// It asserts nothing itself; tests inspect the counters and stores.
package stripetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Server is one fake Stripe instance. Fields are guarded by mu; tests read
// them through the accessor methods.
type Server struct {
	mu sync.Mutex

	server   *httptest.Server
	byIdem   map[string]map[string]any
	prices   map[string]map[string]any
	products map[string]map[string]any

	customers       map[string]map[string]any
	customerOrigin  map[string]string // customer id → acct that created it
	customerReads   map[string]int    // customer id + "|" + acct → reads so far
	propagationLag  int               // sibling-account reads that 404 first
	failDeactivate  int
	failCustCreates int

	creates      int
	priceGets    int
	productGets  int
	customerGets int
}

// New starts a fake Stripe server; it stops with the test.
func New(t *testing.T) *Server {
	t.Helper()
	f := &Server{
		byIdem:         map[string]map[string]any{},
		prices:         map[string]map[string]any{},
		products:       map[string]map[string]any{},
		customers:      map[string]map[string]any{},
		customerOrigin: map[string]string{},
		customerReads:  map[string]int{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

// URL is the base URL to point stripepay at.
func (f *Server) URL() string { return f.server.URL }

// SetPropagationLag makes a shared Customer invisible from the sibling
// account for the first n reads.
func (f *Server) SetPropagationLag(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.propagationLag = n
}

// FailNextDeactivations makes the next n price deactivations return a 500.
func (f *Server) FailNextDeactivations(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDeactivate = n
}

// FailNextCustomerCreates makes the next n customer creations return a 500.
func (f *Server) FailNextCustomerCreates(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCustCreates = n
}

// Creates reports how many objects were genuinely created (idempotent
// replays excluded).
func (f *Server) Creates() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates
}

// Gets reports read counts: prices, products, customers.
func (f *Server) Gets() (prices, products, customers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.priceGets, f.productGets, f.customerGets
}

// PriceActive reports whether a price exists and is active.
func (f *Server) PriceActive(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.prices[id]
	return ok && obj["active"] == true
}

// ActivePriceCount counts active prices — the orphan detector.
func (f *Server) ActivePriceCount() int {
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

// ProductName reads a product's current display name.
func (f *Server) ProductName(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if obj, ok := f.products[id]; ok {
		return obj["name"].(string)
	}
	return ""
}

// CustomerCount reports how many Customers exist.
func (f *Server) CustomerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.customers)
}

func notFound(w http.ResponseWriter, what string) {
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    "resource_missing",
			"type":    "invalid_request_error",
			"message": "No such " + what,
		},
	})
}

func (f *Server) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = r.ParseForm()
	respond := func(obj map[string]any) { _ = json.NewEncoder(w).Encode(obj) }
	context := r.Header.Get("Stripe-Context")

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/products":
		if prior, ok := f.byIdem[r.Header.Get("Idempotency-Key")]; ok {
			respond(prior)
			return
		}
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("prod_%d", f.creates), "object": "product",
			"name": r.PostForm.Get("name"), "active": true,
			"metadata": map[string]any{"portal_slug": r.PostForm.Get("metadata[portal_slug]")},
		}
		f.products[obj["id"].(string)] = obj
		f.byIdem[r.Header.Get("Idempotency-Key")] = obj
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/products/"):
		f.productGets++
		if obj, ok := f.products[strings.TrimPrefix(r.URL.Path, "/v1/products/")]; ok {
			respond(obj)
			return
		}
		notFound(w, "product")

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/products/"):
		obj, ok := f.products[strings.TrimPrefix(r.URL.Path, "/v1/products/")]
		if !ok {
			notFound(w, "product")
			return
		}
		if name := r.PostForm.Get("name"); name != "" {
			obj["name"] = name
		}
		respond(obj)

	case r.Method == http.MethodPost && r.URL.Path == "/v1/prices":
		if prior, ok := f.byIdem[r.Header.Get("Idempotency-Key")]; ok {
			respond(prior)
			return
		}
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("price_%d", f.creates), "object": "price",
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
		f.byIdem[r.Header.Get("Idempotency-Key")] = obj
		respond(obj)

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		obj, ok := f.prices[strings.TrimPrefix(r.URL.Path, "/v1/prices/")]
		if !ok {
			notFound(w, "price")
			return
		}
		if r.PostForm.Get("active") == "false" {
			if f.failDeactivate > 0 {
				f.failDeactivate--
				http.Error(w, `{"error":{"message":"injected failure"}}`, http.StatusInternalServerError)
				return
			}
			obj["active"] = false
		}
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		f.priceGets++
		if obj, ok := f.prices[strings.TrimPrefix(r.URL.Path, "/v1/prices/")]; ok {
			respond(obj)
			return
		}
		notFound(w, "price")

	case r.Method == http.MethodPost && r.URL.Path == "/v1/customers":
		if prior, ok := f.byIdem[r.Header.Get("Idempotency-Key")]; ok {
			respond(prior)
			return
		}
		if f.failCustCreates > 0 {
			f.failCustCreates--
			http.Error(w, `{"error":{"message":"injected failure"}}`, http.StatusInternalServerError)
			return
		}
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("cus_%d", f.creates), "object": "customer",
			"email": r.PostForm.Get("email"), "name": r.PostForm.Get("name"),
			"metadata": map[string]any{"portal_account_id": r.PostForm.Get("metadata[portal_account_id]")},
		}
		id := obj["id"].(string)
		f.customers[id] = obj
		f.customerOrigin[id] = context
		f.byIdem[r.Header.Get("Idempotency-Key")] = obj
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/customers/"):
		f.customerGets++
		id := strings.TrimPrefix(r.URL.Path, "/v1/customers/")
		obj, ok := f.customers[id]
		if !ok {
			notFound(w, "customer")
			return
		}
		// Sharing propagation: reads from the sibling account 404 until the
		// lag is consumed. The origin account always sees its own customer.
		if origin := f.customerOrigin[id]; origin != "" && origin != context {
			key := id + "|" + context
			f.customerReads[key]++
			if f.customerReads[key] <= f.propagationLag {
				notFound(w, "customer")
				return
			}
		}
		respond(obj)

	default:
		http.Error(w, `{"error":{"message":"unexpected `+r.Method+` `+r.URL.Path+`"}}`, http.StatusBadRequest)
	}
}
