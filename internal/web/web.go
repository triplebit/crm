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
	"triplebit.org/portal/internal/httpx"
)

// maxFormBytes bounds every request body. The largest legitimate body this
// portal receives is a small form; anything bigger is a mistake or an attack.
const maxFormBytes = 64 << 10

// Options configures the server. Everything is required unless noted.
type Options struct {
	Sessions *auth.Sessions
	OIDC     *auth.OIDC
	Checkout *checkout.Service

	Jar    *cookie.Jar
	Logger *slog.Logger

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
	case opts.Jar == nil:
		return nil, errors.New("web: a cookie jar is required")
	case opts.BaseURL == nil:
		return nil, errors.New("web: a base URL is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
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
	var root http.Handler = s.mux
	root = httpx.LimitBody(root, maxFormBytes)
	root = httpx.RequireSameOrigin(opts.BaseURL.String(), root)
	if s.trustProxy {
		root, err = httpx.TrustProxyHeaders(opts.TrustedProxyCIDRs, root)
		if err != nil {
			return nil, err
		}
	}
	root = httpx.Middleware{Logger: logger, Production: opts.Production}.Wrap(root)
	return root, nil
}
