package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/cookie"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/csrf"
	"triplebit.org/portal/internal/httpx"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/testdb"
)

// These tests iterate the route REGISTRY, not a hand-written list of paths.
// A new mutating route is covered the moment it is registered; there is no
// second list to forget to update. They construct the Server directly rather
// than through New, so no OIDC discovery is needed — the property under test
// is the registrar, which is the only way a route can exist.

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	pool := testdb.Pool(t)
	repo := accounts.New()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 100)
	}
	ring, err := cryptox.NewKeyring("web-test", map[string][]byte{"web-test": key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	sessions, err := auth.NewSessions(auth.SessionOptions{
		Repo: repo, Pool: pool, Keys: ring,
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	base, _ := url.Parse("http://portal.test")
	jar, err := cookie.NewJar(base, core.Development)
	if err != nil {
		t.Fatalf("NewJar: %v", err)
	}
	limiter, err := httpx.NewRateLimiter(httpx.RateLimitOptions{
		Requests: 1000, Window: time.Minute, MaxKeys: 100,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}

	// StripeProduction, matching the checkout package's fixtures and leaving
	// the sandbox environment to stripesync's. These tests store real pending
	// webhook_events rows, and packages run concurrently against one test
	// database: with both on sandbox, stripesync's projector claimed rows this
	// package had just inserted and failed retrieving sessions its fake Stripe
	// had never heard of. The queue is partitioned by environment by design, so
	// using that partition removes the race rather than narrowing it.
	verifier, err := stripepay.NewWebhookVerifier(core.StripeProduction,
		testMembershipsSecret, testDonationsSecret, testMembershipsAcct, testDonationsAcct)
	if err != nil {
		t.Fatalf("NewWebhookVerifier: %v", err)
	}

	s := &Server{
		mux:           http.NewServeMux(),
		sessions:      sessions,
		webhooks:      verifier,
		inbox:         inbox.New(),
		pool:          pool,
		stripeEnv:     core.StripeProduction,
		now:           func() time.Time { return time.Now().UTC() },
		jar:           jar,
		logger:        slog.New(slog.DiscardHandler),
		authLimiter:   limiter,
		sessionCookie: jar.Name("session"),
		loginCookie:   jar.Name("login"),
		loginTTL:      10 * time.Minute,
		brandName:     "Test Portal",
		brandTagline:  "Testing",
	}
	s.registerRoutes()

	sub := "web-sub-" + uuid.New().String()
	user, err := repo.UpsertBySubject(context.Background(), pool.Conn(), accounts.UpsertUser{
		PocketIDSub: sub, Email: sub + "@example.test", DisplayName: "Web Member",
		EmailVerified: true, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	})
	token, err := sessions.Issue(context.Background(), user.ID, "passkey")
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return s, token.String()
}

func (s *Server) do(t *testing.T, method, path, sessionToken, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "http://portal.test"+path, reader)
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if sessionToken != "" {
		// A raw Cookie header rather than the stdlib cookie type: the lint
		// forbids constructing cookies outside internal/cookie, and a request
		// cookie is just a header — the single-writer rule concerns responses.
		r.Header.Set("Cookie", s.sessionCookie.String()+"="+sessionToken)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

// Every route that is not a GET must have been registered with both
// protections. This is the registry invariant D8 promises: there is no
// registrar method that produces a mutating route without them, and this test
// fails if one is ever added.
func TestRegistryHasNoUnprotectedMutatingRoute(t *testing.T) {
	s, _ := newTestServer(t)

	if len(s.routes) == 0 {
		t.Fatal("the route registry is empty; registerRoutes did not run")
	}
	mutating, webhooks := 0, 0
	for _, rt := range s.routes {
		if rt.Method == http.MethodGet {
			continue
		}
		if rt.Webhook {
			// The declared exception. It carries no session and no CSRF by
			// design — it authenticates the body's signature instead — so what
			// the registry can assert is that the exception is deliberate and
			// that it claims neither protection it does not have.
			webhooks++
			if rt.RequiresSession || rt.ValidatesCSRF {
				t.Errorf("%s %s is a webhook yet claims session/CSRF protection", rt.Method, rt.Pattern)
			}
			continue
		}
		mutating++
		if !rt.RequiresSession {
			t.Errorf("%s %s does not require a session", rt.Method, rt.Pattern)
		}
		if !rt.ValidatesCSRF {
			t.Errorf("%s %s does not validate CSRF", rt.Method, rt.Pattern)
		}
	}
	// D8's exception must stay countable: if this number grows, someone should
	// have to explain why in a review.
	if webhooks > 2 {
		t.Errorf("%d webhook routes; D8 allows one endpoint per Stripe account and no more", webhooks)
	}
	if mutating == 0 {
		t.Fatal("no mutating routes are registered; the assertions above ran against nothing")
	}
}

func TestEveryMutatingRouteRefusesAnonymousRequests(t *testing.T) {
	s, _ := newTestServer(t)

	for _, rt := range s.routes {
		if rt.Method == http.MethodGet || rt.Webhook {
			continue
		}
		w := s.do(t, rt.Method, rt.Pattern, "", "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s without a session: status %d, want 403", rt.Method, rt.Pattern, w.Code)
		}
	}
}

func TestEveryMutatingRouteRefusesRequestsWithoutACSRFToken(t *testing.T) {
	s, token := newTestServer(t)

	for _, rt := range s.routes {
		if rt.Method == http.MethodGet || rt.Webhook {
			continue
		}
		// A live session and no token: the case a cross-site form submission
		// produces, because the browser attaches cookies but the attacker
		// cannot read the token.
		w := s.do(t, rt.Method, rt.Pattern, token, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s without a CSRF token: status %d, want 403", rt.Method, rt.Pattern, w.Code)
		}

		// A syntactically plausible but wrong token must fail identically.
		w = s.do(t, rt.Method, rt.Pattern, token, csrf.FieldName+"=v1.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s with a wrong CSRF token: status %d, want 403", rt.Method, rt.Pattern, w.Code)
		}
	}
}

// The negative tests above would also pass if the router simply returned 403
// for everything, so prove a correctly-authenticated mutation goes through.
func TestSignOutWorksWithSessionAndToken(t *testing.T) {
	s, token := newTestServer(t)

	principal, err := s.sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	csrfToken, err := csrf.Token(principal.CSRFSecret)
	if err != nil {
		t.Fatalf("derive token: %v", err)
	}

	w := s.do(t, http.MethodPost, "/logout", token, csrf.FieldName+"="+url.QueryEscape(csrfToken))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("sign-out: status %d, want 303; body: %s", w.Code, w.Body.String())
	}

	// The session must actually be dead, and the cookie cleared.
	if _, err := s.sessions.Load(context.Background(), token); err == nil {
		t.Error("the session survived sign-out")
	}
	clearsCookie := false
	for _, c := range w.Result().Cookies() {
		if c.Name == s.sessionCookie.String() && c.MaxAge < 0 {
			clearsCookie = true
		}
	}
	if !clearsCookie {
		t.Error("sign-out did not clear the session cookie")
	}
}

func TestAccountRequiresASession(t *testing.T) {
	s, token := newTestServer(t)

	w := s.do(t, http.MethodGet, "/account", "", "")
	if w.Code != http.StatusSeeOther {
		t.Errorf("anonymous /account: status %d, want 303 to home", w.Code)
	}

	w = s.do(t, http.MethodGet, "/account", token, "")
	if w.Code != http.StatusOK {
		t.Errorf("signed-in /account: status %d, want 200", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Web Member") {
		t.Error("/account does not show the member's name — the M3 gate is exactly this")
	}
}

// The sign-in endpoints refuse over-budget clients before doing any work —
// including the session load, so fabricated cookies cannot buy database
// lookups past the limit.
func TestSignInEndpointsAreRateLimited(t *testing.T) {
	s, token := newTestServer(t)
	tight, err := httpx.NewRateLimiter(httpx.RateLimitOptions{
		Requests: 1, Window: time.Minute, MaxKeys: 10,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	s.authLimiter = tight

	// Anonymous callback with no login cookie: handled without touching OIDC.
	if w := s.do(t, http.MethodGet, "/auth/callback", "", ""); w.Code != http.StatusSeeOther {
		t.Fatalf("first callback: status %d, want 303", w.Code)
	}
	// Second request exceeds the budget — and carries a session cookie, which
	// must not be loaded: the refusal happens before the database is asked.
	if w := s.do(t, http.MethodGet, "/auth/callback", token, ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second callback: status %d, want 429", w.Code)
	}
}

// A session sealed under a key the ring no longer holds must not lock the
// member out (500 on every page, /login included) and must not pass silently:
// the router clears the dead cookie and serves the request anonymous, so the
// member's next click signs them back in under the active key.
func TestUnreadableSessionEnvelopeClearsCookieAndServesAnonymous(t *testing.T) {
	s, token := newTestServer(t)

	// The same rows, read through a ring that cannot open the envelope.
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 7)
	}
	rotated, err := cryptox.NewKeyring("web-rotated", map[string][]byte{"web-rotated": otherKey})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	rotatedSessions, err := auth.NewSessions(auth.SessionOptions{
		Repo: accounts.New(), Pool: testdb.Pool(t), Keys: rotated,
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	s.sessions = rotatedSessions

	w := s.do(t, http.MethodGet, "/", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("home with an unreadable session: status %d, want 200 anonymous", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "/login") {
		t.Error("the page did not render the anonymous state")
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == s.sessionCookie.String() && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the dead session cookie was not cleared; the member would carry it forever")
	}
}

// The two route combinations that would be silently broken at request time —
// CSRF without a session (nil-deref on the secret) and CSRF on an exempt
// method (claims protection, validates nothing) — must refuse to register.
func TestImpossibleRouteCombinationsRefuseToRegister(t *testing.T) {
	t.Parallel()
	expectPanic := func(name string, rt route) {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("route %+v registered without panicking", rt)
				}
			}()
			s := &Server{mux: http.NewServeMux()}
			s.register(rt, func(*reqctx) error { return nil })
		})
	}
	expectPanic("csrf without session", route{
		Method: http.MethodPost, Pattern: "/broken", ValidatesCSRF: true,
	})
	expectPanic("csrf on exempt method", route{
		Method: http.MethodGet, Pattern: "/broken", RequiresSession: true, ValidatesCSRF: true,
	})
}
