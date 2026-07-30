package tokens

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestNewProducesDistinctTokensOfTheRightShape(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		tok, err := New(nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s := tok.String()
		if len(s) != 43 { // 32 bytes, unpadded base64url
			t.Fatalf("token %q has length %d, want 43", s, len(s))
		}
		if seen[s] {
			t.Fatalf("token %q was generated twice", s)
		}
		seen[s] = true
	}
}

func TestDigestIsTheSHA256OfTheToken(t *testing.T) {
	t.Parallel()

	tok, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok.String())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := sha256.Sum256(raw)
	if !bytes.Equal(tok.Digest(), want[:]) {
		t.Error("Digest() is not the SHA-256 of the token bytes")
	}
	if len(tok.Digest()) != 32 {
		t.Errorf("digest length = %d, want 32 to match the schema CHECK", len(tok.Digest()))
	}
}

// The database stores only the digest, so a leaked backup must not contain
// anything replayable as a credential.
func TestDigestDoesNotContainTheToken(t *testing.T) {
	t.Parallel()

	tok, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok.String())
	if bytes.Contains(tok.Digest(), raw) {
		t.Error("the digest contains the token bytes")
	}
}

func TestParseRoundTrips(t *testing.T) {
	t.Parallel()

	original, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	parsed, err := Parse(original.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Equal(original) {
		t.Error("a parsed token does not equal the original")
	}
	if !bytes.Equal(parsed.Digest(), original.Digest()) {
		t.Error("a parsed token has a different digest")
	}
}

// One token must map to exactly one digest. Accepting alternative encodings of
// the same bytes would break single-use enforcement, which works by consuming
// the row a digest identifies.
func TestParseRequiresCanonicalEncoding(t *testing.T) {
	t.Parallel()

	// All-ones bytes so the encoding is deterministically full of '_', the
	// base64url character that differs from standard base64. A random token
	// might contain neither '-' nor '_', which would make the standard-base64
	// case below identical to the canonical one and quietly stop testing it.
	tok, err := New(bytes.NewReader(bytes.Repeat([]byte{0xFF}, Size)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	canonical := tok.String()
	if !strings.Contains(canonical, "_") {
		t.Fatalf("fixture %q does not exercise the base64url alphabet", canonical)
	}

	for name, candidate := range map[string]string{
		"empty":            "",
		"too short":        canonical[:42],
		"too long":         canonical + "A",
		"padded":           canonical + "=",
		"standard base64":  strings.ReplaceAll(canonical, "_", "/"),
		"not base64":       strings.Repeat("!", 43),
		"whitespace":       " " + canonical,
		"trailing newline": canonical + "\n",
	} {
		if _, err := Parse(candidate); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%s) error = %v, want ErrMalformed", name, err)
		}
	}
}

func TestZeroTokenIsRecognisable(t *testing.T) {
	t.Parallel()

	var zero Token
	if !zero.IsZero() {
		t.Error("the zero Token does not report IsZero()")
	}
	tok, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tok.IsZero() {
		t.Error("a generated token reported IsZero()")
	}
}

func TestNewFailsWhenTheRandomSourceDoes(t *testing.T) {
	t.Parallel()

	if _, err := New(bytes.NewReader(nil)); err == nil {
		t.Error("New succeeded with an exhausted random source; a short read must never yield a token")
	}
	// A truncated read is also a failure, not a shorter token.
	if _, err := New(bytes.NewReader(make([]byte, Size-1))); err == nil {
		t.Error("New succeeded with insufficient entropy")
	}
}
