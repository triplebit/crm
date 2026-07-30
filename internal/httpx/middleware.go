package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

type contextKey string

const (
	requestIDKey          contextKey = "request-id"
	trustedProxyClientKey contextKey = "trusted-proxy-client"
)

type Middleware struct {
	Logger     *slog.Logger
	Production bool
}

func (m Middleware) Wrap(next http.Handler) http.Handler {
	if m.Logger == nil {
		m.Logger = slog.Default()
	}
	// requestID is outermost because it publishes the ID via the request
	// context, and a context flows inward only: anything outside the
	// middleware that sets it reads an empty value. This ordering was once
	// inverted, and every access log and panic log carried request_id=""
	// while the comments promised otherwise — the test below the middleware
	// asserts the logged ID equals the response header so it cannot silently
	// regress.
	return m.requestID(m.recoverPanic(m.securityHeaders(m.requestLog(next))))
}

// requestIDPattern is what an inbound X-Request-ID must match to be reused.
// The value is echoed into the response header and every log line for the
// request, so arbitrary client bytes are not acceptable; anything that fails
// the pattern is replaced, not rejected.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (m Middleware) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !requestIDPattern.MatchString(requestID) {
			var raw [16]byte
			if _, err := rand.Read(raw[:]); err == nil {
				requestID = hex.EncodeToString(raw[:])
			} else {
				requestID = fmt.Sprintf("%d", time.Now().UnixNano())
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID)))
	})
}

func (m Middleware) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		csp := "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self'"
		if m.Production {
			csp += "; upgrade-insecure-requests"
		}
		header.Set("Content-Security-Policy", csp)
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		if m.Production {
			header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

func (m Middleware) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		m.Logger.InfoContext(r.Context(), "http request",
			"request_id", RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func (m Middleware) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				m.Logger.ErrorContext(r.Context(), "panic recovered",
					"request_id", RequestID(r.Context()),
					"panic", fmt.Sprint(recovered),
					"stack", string(debug.Stack()),
				)
				http.Error(w, "An unexpected error occurred.", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func LimitBody(next http.Handler, bytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, bytes)
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSameOrigin refuses mutating requests that do not come from baseURL.
//
// exemptPaths lists the exact paths this check must skip. It exists for exactly
// one caller shape: an endpoint a third party posts to, authenticated by a
// signature over the body rather than by a cookie. Stripe sends neither Origin
// nor Referer, so without the exemption every webhook delivery is refused
// before any handler runs — settlement would silently never happen. Matching is
// by exact path, and the web layer derives the list from its route registry, so
// a path can only be exempt here if it was registered as a webhook there.
func RequireSameOrigin(baseURL string, exemptPaths []string, next http.Handler) http.Handler {
	baseURL = strings.TrimRight(baseURL, "/")
	exempt := make(map[string]bool, len(exemptPaths))
	for _, path := range exemptPaths {
		exempt[path] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresOriginCheck(r.Method) || exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		// An empty base URL must reject every mutating request, not accept
		// them. Both current callers validate the URL before reaching here,
		// so this is unreachable today — which is exactly when a fail-open
		// default gets forgotten and inherited by a caller that does not.
		if baseURL == "" {
			http.Error(w, "Cross-origin request rejected.", http.StatusForbidden)
			return
		}
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin == "" {
			referer := r.Referer()
			if strings.HasPrefix(referer, baseURL+"/") || referer == baseURL {
				next.ServeHTTP(w, r)
				return
			}
		}
		if origin != baseURL {
			http.Error(w, "Cross-origin request rejected.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

// TrustProxyHeaders resolves the client address only when the immediate
// network peer belongs to an explicitly configured reverse-proxy CIDR. It
// walks X-Forwarded-For from right to left, ignoring trusted proxy hops, so a
// proxy that appends instead of replaces the header cannot make an
// attacker-supplied leftmost address authoritative.
func TrustProxyHeaders(
	trustedCIDRs []string,
	next http.Handler,
) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("trusted-proxy middleware requires a handler")
	}
	if len(trustedCIDRs) == 0 {
		return nil, errors.New(
			"trusted-proxy mode requires at least one proxy CIDR",
		)
	}
	prefixes := make([]netip.Prefix, 0, len(trustedCIDRs))
	for _, raw := range trustedCIDRs {
		raw = strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid trusted proxy CIDR %q: %w",
				raw,
				err,
			)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		peer, ok := remoteIP(request.RemoteAddr)
		if ok && prefixContains(prefixes, peer) {
			if client, valid := forwardedClientIP(
				request.Header.Get("X-Forwarded-For"),
				prefixes,
			); valid {
				ctx := context.WithValue(
					request.Context(),
					trustedProxyClientKey,
					client,
				)
				request = request.WithContext(ctx)
			}
		}
		next.ServeHTTP(writer, request)
	}), nil
}

func ClientIP(request *http.Request, trustProxy bool) string {
	if request == nil {
		return ""
	}
	forwarded, _ := request.Context().Value(
		trustedProxyClientKey,
	).(netip.Addr)
	if trustProxy && forwarded.IsValid() {
		return forwarded.String()
	}
	if peer, ok := remoteIP(request.RemoteAddr); ok {
		return peer.String()
	}
	return ""
}

// forwardedClientIP resolves the client address from X-Forwarded-For by walking
// right to left and returning the first address that parses and is not a
// trusted proxy.
//
// The walk direction is what makes this safe. Only the rightmost entries are
// written by infrastructure we control; everything further left was supplied by
// whoever sent the request, and is never reached once a client address has been
// identified.
//
// An entry that does not parse ends the walk. Anything to its left is
// unverifiable, so it must not be promoted to "the client" — but neither does it
// invalidate the well-formed entries already examined to its right.
//
// That last distinction is a fix, not a refactor. This function previously
// parsed every entry up front and rejected the whole header if any one of them
// failed. Caddy appends to X-Forwarded-For rather than replacing it, so a
// request carrying "X-Forwarded-For: garbage" arrived as "garbage, <real ip>",
// failed to parse, and fell back to the network peer — which is Caddy itself.
// Every such request then shared a single rate-limit bucket keyed on the proxy's
// address, so roughly twenty of them locked every user out of login, checkout
// and account recovery for ten minutes. Walking right to left, the real address
// is found first and the garbage is never examined.
func forwardedClientIP(
	value string,
	trustedProxies []netip.Prefix,
) (netip.Addr, bool) {
	if strings.TrimSpace(value) == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(value, ",")
	for index := len(parts) - 1; index >= 0; index-- {
		raw := strings.TrimSpace(parts[index])
		if raw == "" {
			return netip.Addr{}, false
		}
		parsed, err := netip.ParseAddr(raw)
		if err != nil {
			// Unverifiable from here leftward; stop rather than guess.
			return netip.Addr{}, false
		}
		parsed = parsed.Unmap()
		if !prefixContains(trustedProxies, parsed) {
			return parsed, true
		}
		// A trusted proxy hop: keep walking left for the address it forwarded.
	}
	// Every entry was a trusted proxy, so no client address was forwarded.
	return netip.Addr{}, false
}

func remoteIP(remoteAddress string) (netip.Addr, bool) {
	remoteAddress = strings.TrimSpace(remoteAddress)
	if remoteAddress == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = strings.Trim(remoteAddress, "[]")
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func requiresOriginCheck(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	written, err := r.ResponseWriter.Write(body)
	r.bytes += written
	return written, err
}

// Unwrap lets http.ResponseController reach the underlying writer, so wrapping
// a response in the logging middleware does not silently discard Flusher,
// Hijacker or deadline support.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
