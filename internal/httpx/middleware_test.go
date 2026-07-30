package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireSameOrigin(t *testing.T) {
	handler := RequireSameOrigin("https://members.triplebit.org", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://members.triplebit.org/action", nil)
	request.Header.Set("Origin", "https://evil.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", response.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := (Middleware{Production: true}).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
	if response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("missing HSTS")
	}
}

func TestClientIPHonorsForwardingOnlyFromConfiguredProxyCIDR(
	t *testing.T,
) {
	t.Parallel()
	var observed string
	application := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		observed = ClientIP(request, true)
		writer.WriteHeader(http.StatusNoContent)
	})
	handler, err := TrustProxyHeaders(
		[]string{"10.20.0.0/16", "fd00:1234::/48"},
		application,
	)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.20.3.4:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.42, 10.20.3.4")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if observed != "198.51.100.42" {
		t.Fatalf("trusted proxy client IP = %q", observed)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.20.3.4:4321"
	request.Header.Set(
		"X-Forwarded-For",
		"198.51.100.99, 198.51.100.42",
	)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if observed != "198.51.100.42" {
		t.Fatalf(
			"attacker-controlled leftmost address was trusted: %q",
			observed,
		)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.9:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if observed != "203.0.113.9" {
		t.Fatalf(
			"untrusted peer spoofed forwarded client IP: %q",
			observed,
		)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "[fd00:1234::5]:4321"
	request.Header.Set("X-Forwarded-For", "2001:db8::42")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if observed != "2001:db8::42" {
		t.Fatalf("trusted IPv6 proxy client IP = %q", observed)
	}
}

func TestClientIPRejectsMalformedForwardedAddress(t *testing.T) {
	t.Parallel()
	application := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if got := ClientIP(request, true); got != "10.20.3.4" {
			t.Fatalf("malformed forwarded IP produced %q", got)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	handler, err := TrustProxyHeaders(
		[]string{"10.20.0.0/16"},
		application,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.20.3.4:4321"
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	handler.ServeHTTP(httptest.NewRecorder(), request)
}

func TestTrustedProxyConfigurationFailsClosed(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(
		http.ResponseWriter,
		*http.Request,
	) {
	})
	if _, err := TrustProxyHeaders(nil, next); err == nil {
		t.Fatal("trusted-proxy mode accepted an empty CIDR allowlist")
	}
	if _, err := TrustProxyHeaders(
		[]string{"not-a-cidr"},
		next,
	); err == nil {
		t.Fatal("trusted-proxy mode accepted an invalid CIDR")
	}
}

// The denial-of-service this function previously enabled.
//
// Caddy appends to X-Forwarded-For rather than replacing it, so a request
// arriving with an attacker-chosen header reaches the application as
// "<attacker text>, <real client address>". The old implementation parsed every
// entry before walking and rejected the entire header when any one failed,
// falling back to the network peer — the proxy's own address. Every poisoned
// request then shared one rate-limit bucket, and about twenty of them locked
// every user out of login and checkout for ten minutes.
func TestGarbagePrefixCannotCollapseClientAddressesOntoTheProxy(t *testing.T) {
	t.Parallel()

	const realClient = "198.51.100.42"
	for _, attacker := range []string{
		"garbage",
		"not-an-ip",
		"127.0.0.1; DROP TABLE",
		"<script>",
		"999.999.999.999",
		"10.20.3.4, garbage",
	} {
		t.Run(attacker, func(t *testing.T) {
			var seen string
			application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = ClientIP(r, true)
				w.WriteHeader(http.StatusNoContent)
			})
			handler, err := TrustProxyHeaders([]string{"10.20.0.0/16"}, application)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = "10.20.3.4:4321" // the trusted proxy
			request.Header.Set("X-Forwarded-For", attacker+", "+realClient)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			if seen != realClient {
				t.Errorf("client address = %q, want %q: a poisoned header must not "+
					"collapse every request onto the proxy's own rate-limit bucket", seen, realClient)
			}
		})
	}
}

// Walking right to left must skip our own proxy hops and stop at the first
// address we did not write ourselves.
func TestForwardedWalkSkipsTrustedHops(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		header string
		want   string
	}{
		"single client":            {"198.51.100.42", "198.51.100.42"},
		"client then one hop":      {"198.51.100.42, 10.20.3.4", "198.51.100.42"},
		"client then two hops":     {"198.51.100.42, 10.20.3.4, 10.20.9.9", "198.51.100.42"},
		"spoofed client then real": {"203.0.113.7, 198.51.100.42, 10.20.3.4", "198.51.100.42"},
		"ipv6 client":              {"2001:db8::42, 10.20.3.4", "2001:db8::42"},
	} {
		t.Run(name, func(t *testing.T) {
			var seen string
			application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = ClientIP(r, true)
			})
			handler, err := TrustProxyHeaders([]string{"10.20.0.0/16"}, application)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = "10.20.3.4:4321"
			request.Header.Set("X-Forwarded-For", tc.header)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			if seen != tc.want {
				t.Errorf("client address = %q, want %q", seen, tc.want)
			}
		})
	}
}

// A header naming only trusted proxies carries no client address, so the peer
// must be used rather than a proxy being reported as the client.
func TestForwardedHeaderOfOnlyTrustedHopsFallsBackToPeer(t *testing.T) {
	t.Parallel()

	var seen string
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClientIP(r, true)
	})
	handler, err := TrustProxyHeaders([]string{"10.20.0.0/16"}, application)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.20.3.4:4321"
	request.Header.Set("X-Forwarded-For", "10.20.1.1, 10.20.2.2")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if seen != "10.20.3.4" {
		t.Errorf("client address = %q, want the network peer 10.20.3.4", seen)
	}
}

// An untrusted peer must not be able to forge a client address at all.
func TestForwardedHeaderIsIgnoredFromAnUntrustedPeer(t *testing.T) {
	t.Parallel()

	var seen string
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClientIP(r, true)
	})
	handler, err := TrustProxyHeaders([]string{"10.20.0.0/16"}, application)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.9:4321" // not a configured proxy
	request.Header.Set("X-Forwarded-For", "198.51.100.42")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if seen != "203.0.113.9" {
		t.Errorf("client address = %q, want the peer 203.0.113.9: only a configured "+
			"proxy may assert a forwarded address", seen)
	}
}

func TestRequestIDRejectsUnsafeClientValues(t *testing.T) {
	t.Parallel()
	handler := (Middleware{}).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// A well-formed inbound ID (e.g. set by Caddy) is kept, so a request can
	// be traced across the proxy and the portal.
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Request-ID", "caddy-1234.abc_DEF")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got != "caddy-1234.abc_DEF" {
		t.Errorf("valid inbound request ID was replaced: got %q", got)
	}

	// Anything outside the safe charset is regenerated, never echoed: the
	// value lands in the response header and in every log line.
	for _, unsafe := range []string{
		"id with spaces",
		"quote\"break",
		"non-ascii-\xc3\xa9",
		"semi;colon",
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("X-Request-ID", unsafe)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		got := response.Header().Get("X-Request-ID")
		if got == unsafe || got == "" {
			t.Errorf("unsafe inbound ID %q: got %q, want a regenerated ID", unsafe, got)
		}
	}
}

func TestLoggingMiddlewareDoesNotSwallowFlusher(t *testing.T) {
	t.Parallel()
	handler := (Middleware{}).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The handler sees the statusRecorder wrapper, not the recorder
		// itself; ResponseController must be able to reach through it.
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the middleware chain failed: %v", err)
		}
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if !response.Flushed {
		t.Fatal("Flush never reached the underlying writer")
	}
}

// The request ID must actually reach the logs — requestID publishes it via the
// request context, so it must be the outermost middleware. This was once
// inverted: every access log and panic log carried request_id="" while the
// comments promised otherwise, and no test noticed.
func TestAccessAndPanicLogsCarryTheRealRequestID(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	requestID := func(line string) string {
		var entry struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		return entry.RequestID
	}

	handler := (Middleware{Logger: logger}).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	header := response.Header().Get("X-Request-ID")
	if header == "" {
		t.Fatal("no X-Request-ID header was set")
	}
	logged := requestID(strings.TrimSpace(buf.String()))
	if logged != header {
		t.Errorf("access log request_id = %q, response header = %q; they must match", logged, header)
	}

	// The panic log is emitted by a different middleware and must see the
	// same value.
	buf.Reset()
	handler = (Middleware{Logger: logger}).Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	header = response.Header().Get("X-Request-ID")
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if got := requestID(line); got != header {
			t.Errorf("log line request_id = %q, response header = %q; they must match", got, header)
		}
	}
}
