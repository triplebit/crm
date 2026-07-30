package httpx

import (
	"net/http"
	"net/url"
	"strings"
)

// LocalPath validates a relative in-app path for use in HTTP redirects.
// Unsafe or empty values yield fallback. The returned string is always a
// reconstructed path (and optional query), never the raw input.
func LocalPath(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if path, ok := TryLocalPath(raw); ok {
		return path
	}
	return fallback
}

// TryLocalPath validates a relative in-app path. It returns false for empty
// or unsafe values (open redirects, absolute URLs, control characters).
func TryLocalPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	// CodeQL go/bad-redirect-check–shaped guard: require a single leading slash
	// and reject protocol-relative and backslash-confused targets.
	if raw[0] != '/' ||
		(len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\')) ||
		strings.ContainsAny(raw, "\r\n") {
		return "", false
	}
	raw = strings.ReplaceAll(raw, "\\", "/")
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.IsAbs() ||
		parsed.Host != "" ||
		parsed.Scheme != "" ||
		parsed.Opaque != "" ||
		parsed.User != nil {
		return "", false
	}
	if parsed.Path == "" || parsed.Path[0] != '/' ||
		(len(parsed.Path) > 1 && (parsed.Path[1] == '/' || parsed.Path[1] == '\\')) {
		// Also covers percent-encoded forms such as /%5c and /%2f after decode.
		return "", false
	}
	out := &url.URL{Path: parsed.Path, RawQuery: parsed.RawQuery}
	return out.String(), true
}

// RedirectLocal redirects to a validated relative path. Unsafe values fall
// back to fallback.
func RedirectLocal(
	writer http.ResponseWriter,
	request *http.Request,
	raw, fallback string,
) {
	// LocalPath rejects open redirects; Location is reconstructed.
	http.Redirect(writer, request, LocalPath(raw, fallback), http.StatusSeeOther) // #nosec G710 -- LocalPath rejects open redirects
}
