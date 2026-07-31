// Package web is the portal's HTTP layer: one router, a handful of handlers,
// and the fail-closed registrar that every route must pass through.
package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/cookie"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/httpx"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/stripepay"
)

// maxFormBytes bounds every browser-facing request body. The largest
// legitimate body this portal receives from a browser is a small form;
// anything bigger is a mistake or an attack.
const maxFormBytes = 64 << 10

// maxWebhookBytes bounds a Stripe webhook body, separately and higher, because
// the form cap silently applied to webhooks too and nothing documents that
// every subscribed event stays under 64 KiB. The failure mode of an undersized
// cap is severe and quiet: the read fails, the handler answers 500, Stripe
// retries for three days, and the event is then lost with only log lines — no
// dead letter, because nothing was ever stored. Our subscribed event types
// carry a single API object and are observed well under 64 KiB, so 1 MiB is
// ~16x headroom against payload growth while still bounding what an
// unauthenticated peer can make this handler buffer before signature
// verification refuses it.
const maxWebhookBytes = 1 << 20

// Options configures the server. Everything is required unless noted.
type Options struct {
	Sessions *auth.Sessions
	OIDC     *auth.OIDC
	Checkout *checkout.Service

	// Webhooks verifies Stripe's signatures; Inbox and Pool make a verified
	// event durable. The server does nothing else with an event: the worker
	// projects it.
	Webhooks  *stripepay.WebhookVerifier
	Inbox     *inbox.Repo
	Pool      *db.Pool
	StripeEnv core.StripeEnvironment

	Jar    *cookie.Jar
	Logger *slog.Logger

	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time

	// BaseURL is the public origin, used for the same-origin check on
	// mutating requests.
	BaseURL *url.URL

	BrandName    string
	BrandTagline string
	Production   bool

	// LoginTTL bounds the login cookie's life; it should match the OIDC
	// transaction TTL. Defaults to ten minutes.
	LoginTTL time.Duration

	// TrustedProxyCIDRs enables X-Forwarded-For resolution from those peers
	// only. Empty means the network peer is the client.
	TrustedProxyCIDRs []string
}

// Server holds the wired dependencies and the route registry.
type Server struct {
	mux    *http.ServeMux
	routes []route

	sessions    *auth.Sessions
	oidc        *auth.OIDC
	checkout    *checkout.Service
	webhooks    *stripepay.WebhookVerifier
	inbox       *inbox.Repo
	pool        *db.Pool
	stripeEnv   core.StripeEnvironment
	now         func() time.Time
	jar         *cookie.Jar
	logger      *slog.Logger
	authLimiter *httpx.RateLimiter

	sessionCookie cookie.Name
	loginCookie   cookie.Name
	loginTTL      time.Duration
	trustProxy    bool

	brandName    string
	brandTagline string
}

// New assembles the middleware chain around the routed handlers and returns
// the root handler for the HTTP server.
func New(opts Options) (http.Handler, error) {
	switch {
	case opts.Sessions == nil:
		return nil, errors.New("web: a session manager is required")
	case opts.OIDC == nil:
		return nil, errors.New("web: an OIDC client is required")
	case opts.Checkout == nil:
		return nil, errors.New("web: a checkout service is required")
	case opts.Webhooks == nil:
		return nil, errors.New("web: a webhook verifier is required")
	case opts.Inbox == nil:
		return nil, errors.New("web: a webhook inbox is required")
	case opts.Pool == nil:
		return nil, errors.New("web: a database pool is required")
	case opts.StripeEnv.IsZero():
		return nil, errors.New("web: a Stripe environment is required")
	case opts.Jar == nil:
		return nil, errors.New("web: a cookie jar is required")
	case opts.BaseURL == nil:
		return nil, errors.New("web: a base URL is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	loginTTL := opts.LoginTTL
	if loginTTL <= 0 {
		loginTTL = 10 * time.Minute
	}

	// Sign-in endpoints are rate limited per client address: they do crypto,
	// hit the database and call out to Pocket ID. The right-to-left
	// X-Forwarded-For walk in httpx is what keeps one poisoned header from
	// collapsing every client into the proxy's bucket.
	authLimiter, err := httpx.NewRateLimiter(httpx.RateLimitOptions{
		Requests: 10, Window: time.Minute, MaxKeys: 10_000,
	})
	if err != nil {
		return nil, err
	}

	s := &Server{
		mux:           http.NewServeMux(),
		sessions:      opts.Sessions,
		oidc:          opts.OIDC,
		checkout:      opts.Checkout,
		webhooks:      opts.Webhooks,
		inbox:         opts.Inbox,
		pool:          opts.Pool,
		stripeEnv:     opts.StripeEnv,
		now:           now,
		jar:           opts.Jar,
		logger:        logger,
		authLimiter:   authLimiter,
		sessionCookie: opts.Jar.Name("session"),
		loginCookie:   opts.Jar.Name("login"),
		loginTTL:      loginTTL,
		trustProxy:    len(opts.TrustedProxyCIDRs) > 0,
		brandName:     opts.BrandName,
		brandTagline:  opts.BrandTagline,
	}
	s.registerRoutes()

	// Innermost to outermost: routes, body cap, same-origin on mutations,
	// client-address resolution, then logging/recovery/headers.
	//
	// The same-origin exemption list is derived from the route registry rather
	// than written out, so a path can only be exempt if it was registered as a
	// webhook — which the registrar and its tests already constrain. Writing
	// the paths twice is how the two drift apart.
	var root http.Handler = s.mux
	root = s.limitBodies(root)
	root = httpx.RequireSameOrigin(opts.BaseURL.String(), s.webhookPaths(), root)
	if s.trustProxy {
		root, err = httpx.TrustProxyHeaders(opts.TrustedProxyCIDRs, root)
		if err != nil {
			return nil, err
		}
	}
	root = httpx.Middleware{Logger: logger, Production: opts.Production}.Wrap(root)
	return root, nil
}

// limitBodies applies the body cap each path deserves: the webhook cap on the
// webhook endpoints, the form cap everywhere else. The webhook set is derived
// from the route registry, same as the same-origin exemption below it, so a
// path can only get the larger cap by having been registered as a webhook.
func (s *Server) limitBodies(next http.Handler) http.Handler {
	webhook := make(map[string]bool)
	for _, path := range s.webhookPaths() {
		webhook[path] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxFormBytes)
		if webhook[r.URL.Path] {
			limit = maxWebhookBytes
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
