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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Server is one fake Stripe instance. Fields are guarded by mu; tests read
// them through the accessor methods.
type Server struct {
	mu sync.Mutex

	// prefix makes every identifier this instance mints globally unique:
	// tests share one PostgreSQL, whose unique indexes on Stripe identifiers
	// would otherwise collide across tests that each run their own fake.
	prefix string

	server    *httptest.Server
	byIdem    map[string]map[string]any
	byIdemSig map[string]string // idempotency key → canonical request signature
	byIdemErr map[string]int    // idempotency key → cached error status
	prices    map[string]map[string]any
	products  map[string]map[string]any

	customers       map[string]map[string]any
	sessions        map[string]map[string]any
	subscriptions   map[string]map[string]any
	customerOrigin  map[string]string // customer id → acct that created it
	customerReads   map[string]int    // customer id + "|" + acct → reads so far
	propagationLag  int               // sibling-account reads that 404 first
	failDeactivate  int
	failCustCreates int

	creates      int
	sessionGets  int
	priceGets    int
	productGets  int
	customerGets int
}

// New starts a fake Stripe server; it stops with the test.
func New(t *testing.T) *Server {
	t.Helper()
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	f := &Server{
		prefix:         hex.EncodeToString(raw),
		byIdem:         map[string]map[string]any{},
		byIdemSig:      map[string]string{},
		byIdemErr:      map[string]int{},
		prices:         map[string]map[string]any{},
		products:       map[string]map[string]any{},
		customers:      map[string]map[string]any{},
		sessions:       map[string]map[string]any{},
		subscriptions:  map[string]map[string]any{},
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

// Session returns a stored checkout session's field, or "" when absent.
func (f *Server) Session(id, field string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if obj, ok := f.sessions[id]; ok {
		if v, ok := obj[field].(string); ok {
			return v
		}
	}
	return ""
}

// SettleSession marks a session paid, as Stripe would after a card succeeds,
// optionally attaching a subscription the projector will then retrieve.
func (f *Server) SettleSession(id, paymentIntentID, subscriptionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.sessions[id]
	if !ok {
		return
	}
	obj["payment_status"] = "paid"
	obj["status"] = "complete"
	if paymentIntentID != "" {
		obj["payment_intent"] = map[string]any{"id": paymentIntentID, "object": "payment_intent"}
	}
	if subscriptionID != "" {
		obj["subscription"] = map[string]any{"id": subscriptionID, "object": "subscription"}
		// The session's customer is already an expanded object; reuse it
		// rather than wrapping it a second time.
		f.subscriptions[subscriptionID] = map[string]any{
			"id": subscriptionID, "object": "subscription", "status": "active",
			"cancel_at_period_end": false,
			"customer":             obj["customer"],
			"items": map[string]any{"object": "list", "data": []any{map[string]any{
				"id": "si_" + subscriptionID, "object": "subscription_item",
				"current_period_end": 1900000000,
				"price":              map[string]any{"id": "price_projected", "object": "price"},
			}}},
		}
	}
}

// ExpireSession marks a session expired, as Stripe would after its window.
func (f *Server) ExpireSession(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if obj, ok := f.sessions[id]; ok {
		obj["status"] = "expired"
		obj["payment_status"] = "unpaid"
	}
}

// SessionGets counts canonical retrievals — the projector must read Stripe
// rather than trust a payload, and this is how a test proves it did.
func (f *Server) SessionGets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessionGets
}

// SessionCount reports how many checkout sessions were created.
func (f *Server) SessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
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

	// Stripe caches a request's result under its idempotency key REGARDLESS
	// of whether it succeeded — a replayed key returns the cached response,
	// errors included — and it REFUSES a replay whose parameters differ.
	// Both behaviours are modelled, because a fake that replays regardless of
	// parameters cannot tell a genuinely idempotent retry from a changed
	// request wearing an old key: the crash-recovery tests would pass either
	// way, which is the same as not testing them.
	// Keys are scoped per account, as Stripe scopes them: the same key in two
	// accounts is two independent requests.
	idem := r.Header.Get("Idempotency-Key")
	if idem != "" {
		idem = context + "|" + idem
	}
	signature := canonicalSignature(r, context)
	if idem != "" && r.Method == http.MethodPost {
		if prior, ok := f.byIdemSig[idem]; ok && prior != signature {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"type": "idempotency_error",
				"message": "Keys for idempotent requests can only be used with the same parameters " +
					"they were first used with.",
			}})
			return
		}
		if status, ok := f.byIdemErr[idem]; ok {
			http.Error(w, `{"error":{"message":"cached error replayed for idempotency key"}}`, status)
			return
		}
		if prior, ok := f.byIdem[idem]; ok {
			respond(prior)
			return
		}
		f.byIdemSig[idem] = signature
	}

	failInjected := func(counter *int, idem string) bool {
		if *counter > 0 {
			*counter--
			if idem != "" {
				f.byIdemErr[idem] = http.StatusInternalServerError
			}
			http.Error(w, `{"error":{"message":"injected failure"}}`, http.StatusInternalServerError)
			return true
		}
		return false
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/products":
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("prod_%s%d", f.prefix, f.creates), "object": "product",
			"name": r.PostForm.Get("name"), "active": true,
			"metadata": map[string]any{"portal_slug": r.PostForm.Get("metadata[portal_slug]")},
		}
		f.products[obj["id"].(string)] = obj
		f.byIdem[idem] = obj
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
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("price_%s%d", f.prefix, f.creates), "object": "price",
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
		respond(obj)

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		obj, ok := f.prices[strings.TrimPrefix(r.URL.Path, "/v1/prices/")]
		if !ok {
			notFound(w, "price")
			return
		}
		if r.PostForm.Get("active") == "false" {
			if failInjected(&f.failDeactivate, idem) {
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
		if failInjected(&f.failCustCreates, idem) {
			return
		}
		f.creates++
		obj := map[string]any{
			"id": fmt.Sprintf("cus_%s%d", f.prefix, f.creates), "object": "customer",
			"email": r.PostForm.Get("email"), "name": r.PostForm.Get("name"),
			"metadata": map[string]any{"portal_account_id": r.PostForm.Get("metadata[portal_account_id]")},
		}
		id := obj["id"].(string)
		f.customers[id] = obj
		f.customerOrigin[id] = context
		f.byIdem[idem] = obj
		respond(obj)

	case r.Method == http.MethodPost && r.URL.Path == "/v1/checkout/sessions":
		f.creates++
		id := fmt.Sprintf("cs_test%s%d", f.prefix, f.creates)
		obj := map[string]any{
			"id": id, "object": "checkout.session",
			"url":                  f.server.URL + "/pay/" + id,
			"mode":                 r.PostForm.Get("mode"),
			"customer":             map[string]any{"id": r.PostForm.Get("customer"), "object": "customer"},
			"client_reference_id":  r.PostForm.Get("client_reference_id"),
			"payment_method_types": r.PostForm["payment_method_types[0]"],
			"expires_at":           1900000000,
			"status":               "open",
			"payment_status":       "unpaid",
			"currency":             "usd",
			"amount_total":         0,
		}
		if r.PostForm.Get("shipping_address_collection[allowed_countries][0]") != "" {
			obj["shipping_address_collection"] = map[string]any{
				"allowed_countries": []any{r.PostForm.Get("shipping_address_collection[allowed_countries][0]")},
			}
		}
		f.sessions[id] = obj
		f.byIdem[idem] = obj
		respond(obj)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/expire"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/"), "/expire")
		obj, ok := f.sessions[id]
		if !ok {
			notFound(w, "checkout session")
			return
		}
		// Stripe refuses to expire a session that has completed, and the
		// portal's safety argument depends on that refusal: an error here is
		// how it learns the money arrived and the order must not be abandoned.
		// A fake that expired anything would leave that argument untested.
		if obj["status"] == "complete" || obj["payment_status"] == "paid" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"type":    "invalid_request_error",
				"message": "You may only expire a Checkout Session that is open",
			}})
			return
		}
		obj["status"] = "expired"
		respond(obj)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/checkout/sessions/"):
		f.sessionGets++
		if obj, ok := f.sessions[strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/")]; ok {
			respond(obj)
			return
		}
		notFound(w, "checkout session")

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/subscriptions/"):
		if obj, ok := f.subscriptions[strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")]; ok {
			respond(obj)
			return
		}
		notFound(w, "subscription")

	case r.Method == http.MethodGet && r.URL.Path == "/v1/customers/search":
		// Matches only the metadata query EnsureCustomer's reconciliation
		// uses. Deliberately consistent immediately; the eventual-consistency
		// caveat is handled in the caller's design, not simulated here.
		query := r.URL.Query().Get("query")
		var data []map[string]any
		for _, c := range f.customers {
			meta := c["metadata"].(map[string]any)
			if strings.Contains(query, "'"+meta["portal_account_id"].(string)+"'") {
				data = append(data, c)
				break
			}
		}
		if data == nil {
			data = []map[string]any{}
		}
		respond(map[string]any{"object": "search_result", "data": data, "has_more": false})

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

// canonicalSignature is what Stripe compares on idempotency-key reuse: the
// account context, the endpoint, and every form parameter, in a stable order.
func canonicalSignature(r *http.Request, stripeContext string) string {
	keys := make([]string, 0, len(r.PostForm))
	for k := range r.PostForm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{stripeContext, r.Method, r.URL.Path}
	for _, k := range keys {
		values := append([]string(nil), r.PostForm[k]...)
		sort.Strings(values)
		parts = append(parts, k+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, "|")
}
