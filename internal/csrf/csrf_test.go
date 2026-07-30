package csrf

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func mustSecret(t *testing.T) []byte {
	t.Helper()
	secret, err := NewSecret(nil)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	return secret
}

func TestTokenValidatesAgainstItsOwnSecret(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t)
	token, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if err := Validate(secret, token); err != nil {
		t.Errorf("a freshly minted token was rejected: %v", err)
	}
}

// One token per session: every render within a session emits the same value, so
// no state and no per-path minting is required.
func TestTokenIsDeterministic(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t)
	first, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if first != second {
		t.Errorf("Token is not deterministic: %q then %q", first, second)
	}
}

func TestTokensFromDifferentSecretsDoNotInterchange(t *testing.T) {
	t.Parallel()

	mine, theirs := mustSecret(t), mustSecret(t)
	token, err := Token(theirs)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if err := Validate(mine, token); !errors.Is(err, ErrInvalid) {
		t.Errorf("another session's token validated against this secret: %v", err)
	}
}

func TestValidateRejectsMalformedTokens(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t)
	valid, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	for name, candidate := range map[string]string{
		"empty":          "",
		"no prefix":      strings.TrimPrefix(valid, "v1."),
		"wrong prefix":   "v2." + strings.TrimPrefix(valid, "v1."),
		"truncated":      valid[:len(valid)-1],
		"extended":       valid + "A",
		"absurdly long":  "v1." + strings.Repeat("A", 512),
		"only prefix":    "v1.",
		"different case": strings.ToUpper(valid),
	} {
		if err := Validate(secret, candidate); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%s) error = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSecretMustBeExactlyThirtyTwoBytes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := Token(bytes.Repeat([]byte{7}, size)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Token accepted a %d-byte secret", size)
		}
	}
	if _, err := Token(nil); !errors.Is(err, ErrInvalid) {
		t.Error("Token accepted a nil secret")
	}
}

func TestNewSecretProducesDistinctSecretsOfTheRightSize(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		secret := mustSecret(t)
		if len(secret) != SecretSize {
			t.Fatalf("secret length = %d, want %d", len(secret), SecretSize)
		}
		if seen[string(secret)] {
			t.Fatal("NewSecret produced a duplicate")
		}
		seen[string(secret)] = true
	}
}

func TestRequiredCoversExactlyTheStateChangingMethods(t *testing.T) {
	t.Parallel()

	for method, want := range map[string]bool{
		http.MethodGet:     false,
		http.MethodHead:    false,
		http.MethodOptions: false,
		http.MethodTrace:   false,
		http.MethodPost:    true,
		http.MethodPut:     true,
		http.MethodPatch:   true,
		http.MethodDelete:  true,
		"post":             true, // case-insensitive
		"get":              false,
	} {
		if got := Required(method); got != want {
			t.Errorf("Required(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestValidateRequestAcceptsTheFormFieldAndTheHeader(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t)
	token, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	form := httptest.NewRequest(http.MethodPost, "/checkout",
		strings.NewReader(url.Values{FieldName: {token}}.Encode()))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := form.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if err := ValidateRequest(form, secret); err != nil {
		t.Errorf("a token in the form field was rejected: %v", err)
	}

	header := httptest.NewRequest(http.MethodPost, "/checkout", nil)
	header.Header.Set(HeaderName, token)
	if err := header.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if err := ValidateRequest(header, secret); err != nil {
		t.Errorf("a token in the header was rejected: %v", err)
	}
}

// The token must come from the request body, never the query string. Accepting
// it from the URL would let it leak through browser history, referrers and
// server logs — and the previous implementation's use of FormValue did exactly
// that, while also swallowing body parse errors.
func TestTokenInTheQueryStringIsIgnored(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t)
	token, err := Token(secret)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/checkout?"+FieldName+"="+token, nil)
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if err := ValidateRequest(r, secret); !errors.Is(err, ErrInvalid) {
		t.Errorf("a token supplied in the query string was accepted: %v", err)
	}
}

func TestSafeMethodsNeedNoToken(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/account", nil)
	if err := ValidateRequest(r, mustSecret(t)); err != nil {
		t.Errorf("a GET was rejected for lacking a token: %v", err)
	}
}

func TestMutatingRequestWithNoTokenIsRejected(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/checkout", nil)
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if err := ValidateRequest(r, mustSecret(t)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a POST with no token was accepted: %v", err)
	}
}
