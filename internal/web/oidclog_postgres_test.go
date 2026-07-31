package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/testdb"
	"triplebit.org/portal/internal/tokens"
)

// The refused-sign-in log boundary. A refused OIDC callback used to redirect
// silently, so a misconfigured identity provider produced a member-visible
// failure with no operator signal anywhere; the fix logs "sign-in refused" at
// WARN with the operator-facing cause. That behaviour had no test — and it is
// a boundary worth holding on both sides: the warning must exist, and it must
// not carry the member's login credential, which the handler necessarily holds
// at the moment it logs.
func TestRefusedSignInIsLoggedForTheOperatorWithoutTheCredential(t *testing.T) {
	// A minimal OIDC issuer: discovery only. NewOIDC discovers at startup, and
	// this test's refusal happens before any token exchange, so no other
	// endpoint is ever called.
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer.URL,
			"authorization_endpoint": issuer.URL + "/authorize",
			"token_endpoint":         issuer.URL + "/token",
			"jwks_uri":               issuer.URL + "/jwks",
		})
	}))
	t.Cleanup(issuer.Close)

	s, _ := newTestServer(t)
	oidc, err := auth.NewOIDC(context.Background(), auth.OIDCOptions{
		Issuer: issuer.URL, ClientID: "portal-client", ClientSecret: "secret",
		RedirectURL: "http://portal.test/auth/callback",
		Repo:        accounts.New(), Pool: testdb.Pool(t),
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	s.oidc = oidc
	var logged bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logged, nil))

	// A syntactically valid login token that no transaction ever backed — the
	// shape of an expired tab or a replayed callback. Complete refuses it at
	// the database, before contacting the issuer.
	loginToken, err := tokens.New(nil)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet,
		"http://portal.test/auth/callback?state=some-state&code=some-code", nil)
	r.Header.Set("Cookie", s.loginCookie.String()+"="+loginToken.String())
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)

	// The member gets the vague redirect, as designed.
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303: a refused sign-in redirects with a notice", w.Code)
	}

	// The operator gets the warning, with the cause.
	log := logged.String()
	if !strings.Contains(log, "sign-in refused") {
		t.Fatalf("a refused sign-in left no operator signal; log: %q", log)
	}
	if !strings.Contains(log, "level=WARN") {
		t.Errorf("the refusal is not at WARN — an expired tab must not page anyone; log: %q", log)
	}
	if !strings.Contains(log, "no unconsumed login transaction") {
		t.Errorf("the log does not name the operator-facing cause; log: %q", log)
	}

	// And never the credential. The handler holds the raw login token when it
	// logs; the token appearing here would put a bearer credential in every
	// log aggregator downstream.
	if strings.Contains(log, loginToken.String()) {
		t.Error("the member's login token was written to the log")
	}
}
