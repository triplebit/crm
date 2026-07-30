package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalPath(t *testing.T) {
	t.Parallel()
	const fallback = "/account"
	tests := []struct {
		name  string
		raw   string
		want  string
		ok    bool
		tryOK bool
	}{
		{name: "empty", raw: "", want: fallback, ok: true, tryOK: false},
		{name: "whitespace", raw: "  ", want: fallback, ok: true, tryOK: false},
		{name: "account", raw: "/account", want: "/account", ok: true, tryOK: true},
		{
			name:  "path with query",
			raw:   "/account/claim?token=abc",
			want:  "/account/claim?token=abc",
			ok:    true,
			tryOK: true,
		},
		{name: "protocol relative", raw: "//evil.example/", want: fallback, tryOK: false},
		{name: "backslash confused", raw: "/\\evil.example/", want: fallback, tryOK: false},
		// url.Parse decodes these; the post-parse Path[1] check must keep rejecting them.
		{name: "encoded backslash prefix", raw: "/%5c%5cevil.example/", want: fallback, tryOK: false},
		{name: "encoded backslash prefix upper", raw: "/%5C%5Cevil.example/", want: fallback, tryOK: false},
		{name: "encoded slash prefix", raw: "/%2f%2fevil.example/", want: fallback, tryOK: false},
		{name: "absolute https", raw: "https://evil.example/", want: fallback, tryOK: false},
		{name: "absolute http", raw: "http://evil.example/", want: fallback, tryOK: false},
		{name: "crlf", raw: "/account\r\nLocation: https://evil", want: fallback, tryOK: false},
		{name: "missing slash", raw: "account", want: fallback, tryOK: false},
		{name: "scheme relative backslash", raw: "\\\\evil.example/", want: fallback, tryOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := LocalPath(test.raw, fallback); got != test.want {
				t.Fatalf("LocalPath(%q) = %q, want %q", test.raw, got, test.want)
			}
			got, ok := TryLocalPath(test.raw)
			if ok != test.tryOK {
				t.Fatalf("TryLocalPath(%q) ok = %v, want %v", test.raw, ok, test.tryOK)
			}
			if test.tryOK && got != test.want {
				t.Fatalf("TryLocalPath(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestLocalPathReconstructsNotRaw(t *testing.T) {
	t.Parallel()
	raw := " /account/orders "
	got := LocalPath(raw, "/account")
	if got != "/account/orders" {
		t.Fatalf("LocalPath(%q) = %q, want trimmed reconstructed path", raw, got)
	}
	if got == raw {
		t.Fatal("LocalPath returned the raw input")
	}
}

func TestRedirectLocal(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	RedirectLocal(recorder, request, "//evil.example/", "/account")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if location := recorder.Header().Get("Location"); location != "/account" {
		t.Fatalf("Location = %q, want /account", location)
	}
}
