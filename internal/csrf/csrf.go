// Package csrf issues and validates cross-site request forgery tokens.
//
// One token per session, derived by HMAC from a secret held in the session's
// encrypted envelope. Stateless: there is no server-side token store, and
// revoking the session revokes the token with it.
//
// # Why there is no path binding
//
// The previous implementation bound each token to a specific "METHOD /path", so
// a token minted for one form could not be replayed at another endpoint. That
// sounds strictly better and was not, because the cost was structural: the
// renderer had to know every concrete mutating URL in advance, which produced
// three separate hardcoded lists of paths, seven token-minting sites, a
// 200-line render function, and — because staff URLs contain entity IDs — a
// per-request loop minting fifteen HMACs on every page render.
//
// What it bought was small. To replay a token at a different endpoint an
// attacker must first hold a valid token for the victim's session, which means
// having already rendered a page as the victim, which means having already
// defeated the same-origin policy. Three independent defenses stand before that
// point: a global Origin check on every non-GET request, SameSite=Lax, and the
// __Host- cookie prefix.
//
// If a threat ever justifies re-binding, bind to the *route pattern* the router
// already registers, not to the concrete path. The registry exists; the
// hardcoded lists were the mistake.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	// FieldName is the form field carrying the token.
	FieldName = "_csrf"

	// HeaderName is accepted as an alternative to the form field.
	HeaderName = "X-CSRF-Token"

	// SecretSize is the length of the per-session secret, in bytes. It matches
	// the plaintext size the session envelope is documented to hold.
	SecretSize = 32

	tokenPrefix = "v1."
	maxTokenLen = 256

	// domainSeparator keeps this HMAC distinct from any other use of the same
	// key material. Deriving a purpose-specific value rather than reusing a key
	// directly is the discipline the rest of the codebase follows; the previous
	// implementation broke it once by passing a raw AES key as an HMAC key.
	domainSeparator = "triplebit-csrf:v1\x00"
)

// ErrInvalid is returned for every validation failure. It is deliberately
// singular: telling a caller *why* a token was rejected tells an attacker too.
var ErrInvalid = errors.New("csrf: invalid token")

// NewSecret returns a fresh per-session secret.
func NewSecret(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	secret := make([]byte, SecretSize)
	if _, err := io.ReadFull(random, secret); err != nil {
		return nil, errors.New("csrf: generate secret: " + err.Error())
	}
	return secret, nil
}

// Token derives the session's token from its secret. It is deterministic, so
// every render within a session emits the same value and no state is needed.
func Token(secret []byte) (string, error) {
	if len(secret) != SecretSize {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(domainSeparator))
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Validate reports whether token matches the secret, in constant time.
func Validate(secret []byte, token string) error {
	if len(token) > maxTokenLen || !strings.HasPrefix(token, tokenPrefix) {
		return ErrInvalid
	}
	expected, err := Token(secret)
	if err != nil {
		return ErrInvalid
	}
	if !hmac.Equal([]byte(expected), []byte(token)) {
		return ErrInvalid
	}
	return nil
}

// ValidateRequest checks the token carried by a request.
//
// The token is read from r.PostForm, never from r.FormValue. FormValue also
// consults the query string, which would let a token be supplied in a URL, and
// it parses the body implicitly while discarding any parse error. The caller
// must have called r.ParseForm and checked its error first — the router does
// this before any handler runs.
func ValidateRequest(r *http.Request, secret []byte) error {
	if !Required(r.Method) {
		return nil
	}
	token := r.Header.Get(HeaderName)
	if token == "" {
		token = r.PostForm.Get(FieldName)
	}
	return Validate(secret, token)
}

// Required reports whether a method changes state and therefore needs a token.
func Required(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}
