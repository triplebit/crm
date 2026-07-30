package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/csrf"
	"triplebit.org/portal/internal/httpx"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/web/viewdata"
)

// handler is the only shape a route can take. It is deliberately not
// http.HandlerFunc: a handler receives a *reqctx that only the registrar
// constructs, so there is no type-compatible way to mount an endpoint that
// skips session loading, body limits, ParseForm error checking or CSRF
// validation. Forgetting the protection is a compile error, not a code review
// finding. (D8.)
type handler func(*reqctx) error

// reqctx is what a handler may touch. The raw session token is kept so
// sign-out and rotation can revoke by token; it never renders anywhere.
type reqctx struct {
	w http.ResponseWriter
	r *http.Request

	// principal is nil for an anonymous request. Routes registered with a
	// session requirement never see nil.
	principal  *auth.Principal
	rawSession string

	s *Server
}

// route is one registry entry. The registry exists so tests can iterate every
// registered route and prove the protections hold, rather than trusting a
// hand-written list to stay in sync.
type route struct {
	Method  string
	Pattern string

	// RequiresSession redirects anonymous GETs to the home page and refuses
	// anonymous POSTs outright.
	RequiresSession bool

	// ValidatesCSRF is true for every mutating route except a webhook, which
	// authenticates by signature instead — see Webhook.
	ValidatesCSRF bool

	// Webhook marks the one route shape that mutates without a session or a
	// CSRF token. It is a separate flag rather than an absence so the registry
	// tests can require every exception to be deliberate, and so `grep
	// Webhook` finds all of them.
	Webhook bool

	// RateLimited applies the per-client auth limiter before anything else —
	// including the session load, so a flood of requests bearing fabricated
	// session cookies is refused before it reaches the database.
	RateLimited bool
}

// get registers a public page. A session is loaded when present — pages adapt
// to who is looking at them — but is not required.
func (s *Server) get(pattern string, h handler) {
	s.register(route{Method: http.MethodGet, Pattern: pattern}, h)
}

// getLimited registers a public page behind the per-client auth rate limit.
func (s *Server) getLimited(pattern string, h handler) {
	s.register(route{Method: http.MethodGet, Pattern: pattern, RateLimited: true}, h)
}

// getAuthed registers a page that only a signed-in member can see.
func (s *Server) getAuthed(pattern string, h handler) {
	s.register(route{Method: http.MethodGet, Pattern: pattern, RequiresSession: true}, h)
}

// post registers a mutating route. Session, parsed form and CSRF are
// non-negotiable: there is no variant of this method without them.
func (s *Server) post(pattern string, h handler) {
	s.register(route{
		Method: http.MethodPost, Pattern: pattern,
		RequiresSession: true, ValidatesCSRF: true,
	}, h)
}

// postLimited is post plus the rate limiter, for routes whose handler calls
// Stripe. Stripe's own idempotency stops duplicate charges, but one member
// hammering checkout would still spend the organization's shared API quota
// and degrade every other member's checkout.
func (s *Server) postLimited(pattern string, h handler) {
	s.register(route{
		Method: http.MethodPost, Pattern: pattern,
		RequiresSession: true, ValidatesCSRF: true, RateLimited: true,
	}, h)
}

// Webhook registers the single kind of mutating route that carries no session
// and no CSRF token: an endpoint Stripe posts to.
//
// This is D8's one exception, and it is narrow by construction. A webhook
// cannot use CSRF (there is no page and no session to derive a token from) or
// a session (Stripe is not signed in), so its authentication is the signature
// over the request body — which is strictly stronger than either, because it
// proves the body itself came from Stripe rather than proving a browser had a
// cookie. The handler MUST verify that signature before acting; the registrar
// cannot enforce that, which is precisely why there is exactly one of these
// and it is named.
func (s *Server) webhook(pattern string, h handler) {
	s.register(route{Method: http.MethodPost, Pattern: pattern, Webhook: true}, h)
}

func (s *Server) register(rt route, h handler) {
	// Impossible combinations are refused at startup, not discovered at
	// request time: CSRF validation reads the session's secret, so without a
	// session requirement it is a nil dereference waiting for its first
	// request; and a CSRF flag on a method csrf.Required exempts would claim
	// protection while validating nothing — the registry tests would count it
	// as covered, which is worse than not registering it at all.
	if rt.ValidatesCSRF && !rt.RequiresSession {
		panic(fmt.Sprintf("web: route %s %s validates CSRF without requiring a session", rt.Method, rt.Pattern))
	}
	if rt.ValidatesCSRF && !csrf.Required(rt.Method) {
		panic(fmt.Sprintf("web: route %s %s claims CSRF validation on a method the check exempts", rt.Method, rt.Pattern))
	}
	// A mutating route is protected by CSRF or it is a declared webhook. There
	// is no third option, and forgetting to choose is a startup panic rather
	// than an unprotected endpoint.
	if csrf.Required(rt.Method) && !rt.ValidatesCSRF && !rt.Webhook {
		panic(fmt.Sprintf("web: route %s %s mutates without CSRF and is not a declared webhook",
			rt.Method, rt.Pattern))
	}
	if rt.Webhook && (rt.ValidatesCSRF || rt.RequiresSession) {
		panic(fmt.Sprintf("web: route %s %s is a webhook and cannot also require a session or CSRF",
			rt.Method, rt.Pattern))
	}

	s.routes = append(s.routes, rt)
	s.mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
		c := &reqctx{w: w, r: r, s: s}

		// The limiter runs before the session load for unauthenticated
		// routes, so fabricated cookies cannot buy database lookups. Routes
		// that require a session are limited per member instead, below, since
		// several members can share one NAT address.
		if rt.RateLimited && !rt.RequiresSession {
			allowed, retryAfter := s.authLimiter.Allow(httpx.ClientIP(r, s.trustProxy))
			if !allowed {
				httpx.WriteRateLimitExceeded(w, retryAfter)
				return
			}
		}

		if raw, ok := s.jar.Read(r, s.sessionCookie); ok {
			p, err := s.sessions.Load(r.Context(), raw)
			switch {
			case err == nil:
				c.principal = &p
				c.rawSession = raw
			case errors.Is(err, auth.ErrNoSession):
				// Anonymous: an absent, expired or revoked session is the
				// ordinary signed-out state, not an error.
			case errors.Is(err, auth.ErrSessionUnreadable):
				// The envelope can never be opened again — a dropped rotation
				// key or a corrupt row. Failing the request would lock the
				// member out of every page including /login; staying silent
				// would hide a rotation done wrong. So: loud log, dead cookie
				// cleared, request served anonymous, and the member's next
				// sign-in issues a session under the active key.
				s.logger.ErrorContext(r.Context(), "session envelope unreadable; clearing cookie",
					slog.String("request_id", httpx.RequestID(r.Context())),
					slog.String("error", err.Error()),
				)
				s.jar.Clear(w, s.sessionCookie)
			default:
				// A database failure must not downgrade the request to
				// anonymous — that would present an outage as "signed out"
				// and, on a POST, turn a member's action into a 403 they
				// would retry. Fail closed instead.
				s.fail(c, fmt.Errorf("web: load session: %w", err))
				return
			}
		}

		if rt.RequiresSession && c.principal == nil {
			if rt.Method == http.MethodGet {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			} else {
				http.Error(w, "Sign in to do that.", http.StatusForbidden)
			}
			return
		}

		if rt.RateLimited && rt.RequiresSession {
			allowed, retryAfter := s.authLimiter.Allow("user:" + c.principal.User.ID.String())
			if !allowed {
				httpx.WriteRateLimitExceeded(w, retryAfter)
				return
			}
		}

		if rt.ValidatesCSRF {
			// ParseForm's error is checked, always. The previous
			// implementation used FormValue, which swallows body parse errors
			// and falls back to the query string — so a token could arrive in
			// a URL and a malformed body read as "token absent".
			if err := c.r.ParseForm(); err != nil {
				http.Error(w, "The submitted form could not be read.", http.StatusBadRequest)
				return
			}
			if err := csrf.ValidateRequest(c.r, c.principal.CSRFSecret); err != nil {
				http.Error(w, "The request could not be verified. Reload the page and try again.", http.StatusForbidden)
				return
			}
		}

		if err := h(c); err != nil {
			s.fail(c, err)
		}
	})
}

// fail renders an error without disclosing it. The full chain goes to the log;
// the browser sees a safe sentence and a request ID to quote, which is the
// same ID the log line carries — that correspondence is what makes a member's
// support message findable.
func (s *Server) fail(c *reqctx, err error) {
	requestID := httpx.RequestID(c.r.Context())
	// A safe error is an expected, member-actionable rejection — it must not
	// count against error-rate alerting, which is the whole reason it carries
	// its own status. WARN keeps it visible; ERROR would page someone for a
	// support case.
	level := slog.LevelError
	if safeerr.IsSafe(err) {
		level = slog.LevelWarn
	}
	s.logger.Log(c.r.Context(), level, "request failed",
		slog.String("request_id", requestID),
		slog.String("method", c.r.Method),
		slog.String("path", c.r.URL.Path),
		slog.String("error", err.Error()),
	)
	message := safeerr.Message(err, "Something went wrong. Please try again.")
	if requestID != "" {
		message += " (request " + requestID + ")"
	}
	// A safe error may carry its own status: a permanent, member-actionable
	// refusal (409, 422, ...) is not a server fault and must not count as one.
	http.Error(c.w, message, safeerr.StatusOf(err, http.StatusInternalServerError))
}

// layout builds the frame every page shares. The CSRF token is derived here,
// once per render, from the per-session secret that never leaves the server.
func (c *reqctx) layout(title string) (viewdata.Layout, error) {
	l := viewdata.Layout{
		BrandName:    c.s.brandName,
		BrandTagline: c.s.brandTagline,
		Title:        title,
	}
	if c.principal != nil {
		token, err := csrf.Token(c.principal.CSRFSecret)
		if err != nil {
			return viewdata.Layout{}, fmt.Errorf("web: derive CSRF token: %w", err)
		}
		l.SignedIn = true
		l.UserName = c.principal.User.DisplayName
		if l.UserName == "" {
			l.UserName = c.principal.User.Email
		}
		l.CSRFToken = token
	}
	return l, nil
}
