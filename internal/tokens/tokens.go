// Package tokens issues opaque bearer tokens and the digests used to store
// them.
//
// The rule this package enforces: the holder gets 32 random bytes, and the
// database gets only their SHA-256 digest. A leaked database backup therefore
// contains nothing that can be replayed as a credential, and a token cannot be
// reconstructed from what is stored.
//
// This shape is shared by the browser session token and by the OIDC login
// transaction, so it is written once. It deliberately does *not* encode any
// payload. The previous implementation's guest-donation claim token carried the
// donor's email address inside a signed-but-unencrypted URL parameter, which put
// an address into browser history, copied links and any upstream log — and its
// replay nonce was generated but never stored, so the link stayed valid for its
// full 24-hour lifetime. An opaque token plus a server-side row avoids all of
// that: the payload lives in the database, and consuming the row is what makes a
// token single-use.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Size is the number of random bytes in a token.
const Size = 32

// ErrMalformed is returned for anything that is not a canonical token.
var ErrMalformed = errors.New("tokens: malformed token")

// Token is an opaque bearer secret. It is comparable, but comparing tokens
// directly is not how they are used: look the digest up instead.
type Token struct {
	raw [Size]byte
}

// New returns a fresh token from the given source, or crypto/rand when nil.
func New(random io.Reader) (Token, error) {
	if random == nil {
		random = rand.Reader
	}
	var t Token
	if _, err := io.ReadFull(random, t.raw[:]); err != nil {
		return Token{}, fmt.Errorf("tokens: generate: %w", err)
	}
	return t, nil
}

// Parse decodes a token presented by a client.
//
// Encoding must be canonical: the value is re-encoded and compared, so
// alternative encodings of the same bytes are rejected rather than treated as
// equivalent. That keeps one token to one digest, which is what makes
// single-use enforcement by digest lookup sound.
func Parse(s string) (Token, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(decoded) != Size {
		return Token{}, ErrMalformed
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != s {
		return Token{}, ErrMalformed
	}
	var t Token
	copy(t.raw[:], decoded)
	return t, nil
}

// String returns the value handed to the client: 43 unpadded base64url
// characters.
func (t Token) String() string { return base64.RawURLEncoding.EncodeToString(t.raw[:]) }

// Digest returns the SHA-256 of the token. This, and only this, is stored.
func (t Token) Digest() []byte {
	sum := sha256.Sum256(t.raw[:])
	return sum[:]
}

// Equal compares two tokens in constant time.
func (t Token) Equal(other Token) bool {
	return subtle.ConstantTimeCompare(t.raw[:], other.raw[:]) == 1
}

// IsZero reports whether t is the unusable zero value.
func (t Token) IsZero() bool { return t == Token{} }
