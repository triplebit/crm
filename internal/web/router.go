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

	// ValidatesCSRF is true for every mutating route. A future router.Webhook
	// will be the single, greppable exception; until one exists there is no
	// exception at all.
	ValidatesCSRF bool

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

func (s *Server) register(rt route, h handler) {
	s.routes = append(s.routes, rt)
	s.mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
		c := &reqctx{w: w, r: r, s: s}

		if rt.RateLimited {
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
// the browser sees a safe sentence and a request ID to quote.
func (s *Server) fail(c *reqctx, err error) {
	s.logger.ErrorContext(c.r.Context(), "request failed",
		slog.String("request_id", httpx.RequestID(c.r.Context())),
		slog.String("method", c.r.Method),
		slog.String("path", c.r.URL.Path),
		slog.String("error", err.Error()),
	)
	message := safeerr.Message(err, "Something went wrong. Please try again.")
	http.Error(c.w, message, http.StatusInternalServerError)
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
