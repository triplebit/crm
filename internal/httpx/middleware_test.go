package httpx

import (
	"net/http"
	"net/http/httptest"
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
