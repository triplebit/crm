package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/testdb"
)

// fakeIdP is a minimal but honest OIDC provider: real discovery, real JWKS,
// and RS256-signed ID tokens that go-oidc verifies cryptographically. Testing
// against it exercises the same code paths as Pocket ID will, which matters in
// a project whose predecessor shipped a login that had never once succeeded.
type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	// claims for the next token, mutable per test case.
	subject       string
	email         string
	emailVerified bool
	name          string
	amr           []string
	nonceOverride string // when set, signed into the token instead of the request's nonce

	issuedCode    string
	codeChallenge string
	nonce         string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	idp := &fakeIdP{
		key:           key,
		subject:       "pocket-id-subject-1",
		email:         "member@example.test",
		emailVerified: true,
		name:          "Test Member",
		amr:           []string{"webauthn"},
		issuedCode:    "authorization-code-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/authorize",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := &idp.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if got := r.PostForm.Get("code"); got != idp.issuedCode {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		// PKCE: the exchange must present the verifier whose S256 digest was
		// sent at authorization time. Refusing here is what proves the client
		// really implements PKCE rather than merely claiming to.
		verifier := r.PostForm.Get("code_verifier")
		digest := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(digest[:]) != idp.codeChallenge {
			http.Error(w, "PKCE verifier mismatch", http.StatusBadRequest)
			return
		}
		nonce := idp.nonce
		if idp.nonceOverride != "" {
			nonce = idp.nonceOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token-1",
			"token_type":   "bearer",
			"id_token":     idp.signIDToken(t, nonce),
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIdP) signIDToken(t *testing.T, nonce string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "test-key"}
	claims := map[string]any{
		"iss":            idp.server.URL,
		"aud":            "portal-client",
		"sub":            idp.subject,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(5 * time.Minute).Unix(),
		"nonce":          nonce,
		"email":          idp.email,
		"email_verified": idp.emailVerified,
		"name":           idp.name,
		"amr":            idp.amr,
	}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal JWT part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// begin runs Begin and captures what the IdP would see from the redirect.
func (idp *fakeIdP) begin(t *testing.T, client *auth.OIDC) (loginToken, state string) {
	t.Helper()
	authURL, token, err := client.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", query.Get("code_challenge_method"))
	}
	if got := query.Get("scope"); got != "openid profile email" {
		t.Fatalf("scope = %q, want exactly \"openid profile email\": authorization comes from PostgreSQL, never from a groups claim", got)
	}
	idp.codeChallenge = query.Get("code_challenge")
	idp.nonce = query.Get("nonce")
	return token.String(), query.Get("state")
}

func newOIDC(t *testing.T, idp *fakeIdP) *auth.OIDC {
	t.Helper()
	client, err := auth.NewOIDC(context.Background(), auth.OIDCOptions{
		Issuer:       idp.server.URL,
		ClientID:     "portal-client",
		ClientSecret: "portal-secret",
		RedirectURL:  "https://portal.example/auth/callback",
		Repo:         accounts.New(),
		Pool:         testdb.Pool(t),
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return client
}

func TestSignInRoundTrip(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	client := newOIDC(t, idp)

	loginToken, state := idp.begin(t, client)
	identity, err := client.Complete(ctx, loginToken, state, idp.issuedCode)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if identity.Subject != idp.subject {
		t.Errorf("subject = %q, want %q", identity.Subject, idp.subject)
	}
	if identity.Email != idp.email {
		t.Errorf("email = %q, want %q", identity.Email, idp.email)
	}
	if identity.DisplayName != idp.name {
		t.Errorf("display name = %q, want %q", identity.DisplayName, idp.name)
	}
	if identity.LoginMethod != "passkey" {
		t.Errorf("login method = %q, want passkey (amr carried webauthn)", identity.LoginMethod)
	}
}

func TestCallbackWithWrongStateFails(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	client := newOIDC(t, idp)

	loginToken, _ := idp.begin(t, client)
	if _, err := client.Complete(ctx, loginToken, "attacker-supplied-state", idp.issuedCode); err == nil {
		t.Fatal("a callback with the wrong state was accepted")
	}
}

func TestCallbackCannotBeReplayed(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	client := newOIDC(t, idp)

	loginToken, state := idp.begin(t, client)
	if _, err := client.Complete(ctx, loginToken, state, idp.issuedCode); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	if _, err := client.Complete(ctx, loginToken, state, idp.issuedCode); err == nil {
		t.Fatal("a replayed callback was accepted; the login transaction must be single-use")
	}
}

func TestUnverifiedEmailIsRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	idp.emailVerified = false
	client := newOIDC(t, idp)

	loginToken, state := idp.begin(t, client)
	if _, err := client.Complete(ctx, loginToken, state, idp.issuedCode); err == nil {
		t.Fatal("an identity with an unverified email was accepted")
	}
}

func TestTamperedNonceIsRejected(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP(t)
	idp.nonceOverride = "a-nonce-from-some-other-login"
	client := newOIDC(t, idp)

	loginToken, state := idp.begin(t, client)
	if _, err := client.Complete(ctx, loginToken, state, idp.issuedCode); err == nil {
		t.Fatal("an ID token whose nonce does not match the transaction was accepted")
	}
}

func TestSignInCreatesUserAndSession(t *testing.T) {
	ctx := context.Background()
	sessions, _, _ := newSessions(t)
	pool := testdb.Pool(t)

	sub := "signin-sub-" + fmt.Sprint(time.Now().UnixNano())
	user, token, err := sessions.SignIn(ctx, auth.Identity{
		Subject:       sub,
		Email:         sub + "@example.test",
		EmailVerified: true,
		DisplayName:   "Signed In Member",
		LoginMethod:   "passkey",
	})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	})

	principal, err := sessions.Load(ctx, token.String())
	if err != nil {
		t.Fatalf("the session issued by SignIn did not load: %v", err)
	}
	if principal.User.ID != user.ID {
		t.Errorf("principal user = %v, want %v", principal.User.ID, user.ID)
	}
	if !strings.EqualFold(principal.User.Email, sub+"@example.test") {
		t.Errorf("principal email = %q", principal.User.Email)
	}
}

// A second Pocket ID subject asserting an email that already belongs to
// someone else trips the schema's one-account-per-email index. That must
// surface as a safe, human-readable refusal — not an opaque 500 on every
// attempt — and case-only variants must collide too, because the index is on
// lower(email).
func TestSignInWithAnotherAccountsEmailFailsSafely(t *testing.T) {
	ctx := context.Background()
	sessions, _, _ := newSessions(t)
	pool := testdb.Pool(t)

	email := fmt.Sprintf("shared-%d@example.test", time.Now().UnixNano())
	first, _, err := sessions.SignIn(ctx, auth.Identity{
		Subject: "subject-a-" + email, Email: email, EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("first SignIn: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, first.ID)
	})

	_, _, err = sessions.SignIn(ctx, auth.Identity{
		Subject: "subject-b-" + email, Email: strings.ToUpper(email), EmailVerified: true,
	})
	if err == nil {
		t.Fatal("a second subject claimed an existing email and was accepted")
	}
	if !safeerr.IsSafe(err) {
		t.Errorf("the collision error %v is not safe to render; the member would see a blank 500 forever", err)
	}
	// A member-actionable refusal, not a server fault: it must not render as
	// a 500, which would pollute error-rate alerting with support cases.
	if got := safeerr.StatusOf(err, http.StatusInternalServerError); got != http.StatusConflict {
		t.Errorf("collision status = %d, want %d", got, http.StatusConflict)
	}
}
