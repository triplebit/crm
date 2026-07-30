package cookie

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"triplebit.org/portal/internal/core"
)

func mustJar(t *testing.T, raw string, env core.Environment) *Jar {
	t.Helper()
	base, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	jar, err := NewJar(base, env)
	if err != nil {
		t.Fatalf("NewJar(%q, %v): %v", raw, env, err)
	}
	return jar
}

func setHeader(t *testing.T, jar *Jar, name Name, value string, expires time.Time) string {
	t.Helper()
	rec := httptest.NewRecorder()
	jar.Set(rec, name, value, expires)
	got := rec.Header().Get("Set-Cookie")
	if got == "" {
		t.Fatal("no Set-Cookie header was written")
	}
	return got
}

// The bug this package exists to prevent. A __Host- prefixed cookie is silently
// discarded by every browser unless Path=/, and the previous implementation
// shipped one with Path=/account.
func TestHostPrefixedCookiesAlwaysUseTheRootPath(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	header := setHeader(t, jar, jar.Name("session"), "value", time.Time{})

	if !strings.Contains(header, "__Host-") {
		t.Fatalf("Set-Cookie %q does not use the __Host- prefix over https", header)
	}
	if !strings.Contains(header, "Path=/;") && !strings.HasSuffix(header, "Path=/") {
		t.Errorf("Set-Cookie %q does not set Path=/, so the browser will discard it", header)
	}
	if strings.Contains(header, "Domain=") {
		t.Errorf("Set-Cookie %q sets Domain, which __Host- forbids", header)
	}
}

func TestSecureCookiesCarryTheExpectedAttributes(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	header := setHeader(t, jar, jar.Name("session"), "value", time.Time{})

	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(header, want) {
			t.Errorf("Set-Cookie %q is missing %s", header, want)
		}
	}
}

// Over plain http the __Host- prefix cannot be used, because it implies Secure.
// Emitting it anyway would mean the cookie is silently dropped in development.
func TestPlainHTTPDropsThePrefixAndTheSecureAttribute(t *testing.T) {
	jar := mustJar(t, "http://localhost:8080", core.Development)
	header := setHeader(t, jar, jar.Name("session"), "value", time.Time{})

	if strings.Contains(header, "__Host-") {
		t.Errorf("Set-Cookie %q uses __Host- over http, so the browser will discard it", header)
	}
	if strings.Contains(header, "Secure") {
		t.Errorf("Set-Cookie %q is Secure over http, so the browser will discard it", header)
	}
	if !strings.Contains(header, "HttpOnly") {
		t.Errorf("Set-Cookie %q is not HttpOnly; that is never relaxed", header)
	}
}

// A misconfigured production deployment must fail at startup, not serve session
// cookies in clear text.
func TestProductionRefusesANonHTTPSBaseURL(t *testing.T) {
	base, err := url.Parse("http://members.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewJar(base, core.Production); err == nil {
		t.Error("production accepted an http base URL; session cookies would not be Secure")
	}
	if _, err := NewJar(nil, core.Production); err == nil {
		t.Error("a nil base URL was accepted")
	}
}

func TestZeroNamePanicsRatherThanWritingAnEmptyCookieName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("the zero Name did not panic")
		}
	}()
	var zero Name
	_ = zero.String()
}

func TestNameRejectsAnythingUnexpected(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	for _, bad := range []string{"", "Session", "with-dash", "__Host-session", "a/b", strings.Repeat("x", 65)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Name(%q) was accepted", bad)
				}
			}()
			_ = jar.Name(bad)
		}()
	}
}

func TestClearExpiresTheCookieImmediately(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	rec := httptest.NewRecorder()
	jar.Clear(rec, jar.Name("session"))

	header := rec.Header().Get("Set-Cookie")
	if !strings.Contains(header, "Max-Age=0") {
		t.Errorf("Set-Cookie %q does not expire the cookie", header)
	}
	if !strings.Contains(header, "Path=/") {
		t.Errorf("Set-Cookie %q clears a different path than it set", header)
	}
}

func TestReadRoundTripsAValue(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	name := jar.Name("session")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := jar.Read(r, name); ok {
		t.Error("a missing cookie was reported as present")
	}

	r.AddCookie(&http.Cookie{Name: name.String(), Value: "abc"})
	got, ok := jar.Read(r, name)
	if !ok || got != "abc" {
		t.Errorf("Read = (%q, %v), want (\"abc\", true)", got, ok)
	}
}

func TestEmptyCookieValueIsTreatedAsAbsent(t *testing.T) {
	jar := mustJar(t, "https://members.example.org", core.Production)
	name := jar.Name("session")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: name.String(), Value: ""})
	if _, ok := jar.Read(r, name); ok {
		t.Error("an empty cookie was reported as present")
	}
}
