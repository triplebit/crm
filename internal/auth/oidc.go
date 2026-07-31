package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/tokens"
)

// ErrLoginFailed means an OIDC callback could not be completed. Every cause
// matches it — unknown or expired transaction, state mismatch, failed exchange,
// bad token, unverified email — because the MEMBER's remedy is always the same
// (start over), and distinguishing causes for the member distinguishes them for
// an attacker.
//
// Each return site wraps it with a cause for the operator. That distinction is
// the whole point: the member sees one vague sentence, the log names the reason.
// Before this, nine refusals returned the bare error and the handler logged
// nothing, so a misconfigured identity provider presented as an unexplained
// "Sign-in could not be completed" and had to be diagnosed by reading Pocket
// ID's own database. Use errors.Is, never equality, to test for it.
var ErrLoginFailed = errors.New("auth: sign-in could not be completed")

// Identity is what a completed Pocket ID sign-in asserts about a person.
// It carries claims, not authorization: what the person may do is decided by
// PostgreSQL rows, never by anything in a token.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	LoginMethod   string
}

// scopes is fixed. The previous implementation allowed scopes to be configured
// and then had to strip "groups" defensively at runtime, because authorization
// must come from the database, never from a token. Making the slice a constant
// of this package removes the configuration surface entirely: there is nothing
// to strip because there is no way to ask.
var scopes = []string{oidc.ScopeOpenID, "profile", "email"}

// OIDCOptions configures the Pocket ID client.
type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string

	Repo *accounts.Repo
	Pool *db.Pool

	// TransactionTTL bounds how long a sign-in may sit between the redirect to
	// Pocket ID and the callback. Defaults to ten minutes.
	TransactionTTL time.Duration
	Now            func() time.Time
}

// OIDC runs the Authorization Code + PKCE flow against Pocket ID.
type OIDC struct {
	repo     *accounts.Repo
	pool     *db.Pool
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	ttl      time.Duration
	now      func() time.Time
}

// NewOIDC discovers the issuer and builds the client. Discovery at startup is
// deliberate: an unreachable or misconfigured Pocket ID should stop the process
// from starting, not surface as a broken login page later.
func NewOIDC(ctx context.Context, opts OIDCOptions) (*OIDC, error) {
	switch {
	case opts.Issuer == "":
		return nil, errors.New("auth: an OIDC issuer is required")
	case opts.ClientID == "":
		return nil, errors.New("auth: an OIDC client ID is required")
	case opts.ClientSecret == "":
		return nil, errors.New("auth: an OIDC client secret is required")
	case opts.RedirectURL == "":
		return nil, errors.New("auth: an OIDC redirect URL is required")
	case opts.Repo == nil:
		return nil, errors.New("auth: an accounts repository is required")
	case opts.Pool == nil:
		return nil, errors.New("auth: a database pool is required")
	}
	ttl := opts.TransactionTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: discover OIDC issuer: %w", err)
	}
	return &OIDC{
		repo:     opts.Repo,
		pool:     opts.Pool,
		verifier: provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		oauth: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		ttl: ttl,
		now: now,
	}, nil
}

// Begin starts a sign-in: it stores the transaction server-side and returns the
// authorization URL to redirect to, plus the opaque token for the login cookie.
//
// The browser learns only the token. State travels to Pocket ID as usual, but
// the values the callback must check — state, nonce, PKCE verifier — exist
// nowhere outside the database row.
func (o *OIDC) Begin(ctx context.Context) (authURL string, loginToken tokens.Token, err error) {
	loginToken, err = tokens.New(nil)
	if err != nil {
		return "", tokens.Token{}, err
	}
	// State and nonce are opaque random values with the same entropy
	// requirements as a bearer token, so the token generator is reused rather
	// than paralleled.
	stateToken, err := tokens.New(nil)
	if err != nil {
		return "", tokens.Token{}, err
	}
	nonceToken, err := tokens.New(nil)
	if err != nil {
		return "", tokens.Token{}, err
	}
	pkceVerifier := oauth2.GenerateVerifier()

	now := o.now().UTC()
	err = o.repo.CreateLoginTransaction(ctx, o.pool.Conn(), accounts.LoginTransaction{
		TokenDigest:  loginToken.Digest(),
		State:        stateToken.String(),
		Nonce:        nonceToken.String(),
		PKCEVerifier: pkceVerifier,
		CreatedAt:    now,
		ExpiresAt:    now.Add(o.ttl),
	})
	if err != nil {
		return "", tokens.Token{}, err
	}

	authURL = o.oauth.AuthCodeURL(
		stateToken.String(),
		oidc.Nonce(nonceToken.String()),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
	return authURL, loginToken, nil
}

// Complete finishes a sign-in: it consumes the server-side transaction, checks
// state, exchanges the code with the PKCE verifier, verifies the ID token and
// its nonce, and returns the asserted identity.
//
// The transaction is consumed before anything else, so a replayed callback —
// same URL pasted twice, a retried request — finds nothing to match and fails
// without contacting Pocket ID.
func (o *OIDC) Complete(ctx context.Context, rawLoginToken, state, code string) (Identity, error) {
	loginToken, err := tokens.Parse(rawLoginToken)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: the login cookie is not a valid token", ErrLoginFailed)
	}
	tx, err := o.repo.ConsumeLoginTransaction(ctx, o.pool.Conn(), loginToken.Digest(), o.now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return Identity{}, fmt.Errorf(
				"%w: no unconsumed login transaction matches this cookie (expired, "+
					"already used, or a replayed callback)", ErrLoginFailed)
		}
		// A database failure is an outage, not a bad login; the caller must not
		// present it as "try signing in again".
		return Identity{}, err
	}
	if subtle.ConstantTimeCompare([]byte(tx.State), []byte(state)) != 1 {
		return Identity{}, fmt.Errorf("%w: the state parameter does not match the login transaction", ErrLoginFailed)
	}

	oauthToken, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(tx.PKCEVerifier))
	if err != nil {
		// Includes a client-secret mismatch and a PKCE rejection, which look
		// identical to a member and very different to an operator.
		return Identity{}, fmt.Errorf("%w: the token exchange failed: %v", ErrLoginFailed, err)
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("%w: the token response carried no id_token", ErrLoginFailed)
	}
	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Issuer, audience, signature or expiry. An issuer mismatch here is the
		// classic "PORTAL_OIDC_ISSUER does not equal Pocket ID's APP_URL".
		return Identity{}, fmt.Errorf("%w: the ID token did not verify: %v", ErrLoginFailed, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(tx.Nonce)) != 1 {
		return Identity{}, fmt.Errorf("%w: the ID token nonce does not match the login transaction", ErrLoginFailed)
	}

	var claims struct {
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		AMR               []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("%w: the ID token claims could not be decoded: %v", ErrLoginFailed, err)
	}
	// An unverified address must never enter the users table: email is how
	// staff reach a member, and accepting an unverified one would let anyone
	// register an account that appears to belong to someone else.
	//
	// The reasons are named because they are not interchangeable. Every refusal
	// in this function used to return a bare ErrLoginFailed, so nine distinct
	// causes produced one indistinguishable outcome, the handler logged nothing,
	// and diagnosing a real failure meant reading the identity provider's
	// database. The member still sees one deliberately vague sentence; the
	// operator now gets the cause.
	switch {
	case idToken.Subject == "":
		return Identity{}, fmt.Errorf("%w: the ID token carries no subject", ErrLoginFailed)
	case claims.Email == "":
		return Identity{}, fmt.Errorf("%w: the ID token carries no email address", ErrLoginFailed)
	case !claims.EmailVerified:
		return Identity{}, fmt.Errorf(
			"%w: Pocket ID reports this email as unverified, and an unverified "+
				"address must never enter the users table. Verify it in Pocket ID, "+
				"or set EMAILS_VERIFIED=true there for a development instance",
			ErrLoginFailed)
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}
	return Identity{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   displayName,
		LoginMethod:   loginMethodFromAMR(claims.AMR),
	}, nil
}

// SignIn records a completed sign-in: it creates or refreshes the user from the
// asserted identity, then issues a fresh session. The caller must revoke any
// prior session before storing the returned token in the cookie, so a login
// always rotates the credential.
func (s *Sessions) SignIn(ctx context.Context, id Identity) (accounts.User, tokens.Token, error) {
	user, err := s.repo.UpsertBySubject(ctx, s.pool.Conn(), accounts.UpsertUser{
		PocketIDSub:   id.Subject,
		Email:         id.Email,
		DisplayName:   id.DisplayName,
		EmailVerified: id.EmailVerified,
		Now:           s.now().UTC(),
	})
	if err != nil {
		// The upsert is keyed on the Pocket ID subject, but the schema also
		// enforces one account per lower(email). A new subject asserting an
		// email that already belongs to a different subject — a reassigned
		// address, a second IdP account, a case-only variant — trips that
		// index, and without this branch it would render as an opaque 500 on
		// every sign-in attempt, forever. The member gets a sentence a human
		// can act on, with a conflict status so it never pages anyone.
		//
		// Whether identity is "one person per subject" (drop the email index)
		// or "one person per email" (link accounts by verified email) is an
		// open product decision recorded in the roadmap; until it is made,
		// this surfaces the collision instead of resolving it.
		if db.ConstraintOf(err) == "users_email_normalized_idx" {
			return accounts.User{}, tokens.Token{}, safeerr.WithStatus(http.StatusConflict,
				"This email address already belongs to a different account. Please contact support.")
		}
		return accounts.User{}, tokens.Token{}, err
	}
	token, err := s.Issue(ctx, user.ID, id.LoginMethod)
	if err != nil {
		return accounts.User{}, tokens.Token{}, err
	}
	return user, token, nil
}

// loginMethodFromAMR maps the amr claim onto the values the schema permits.
// Passkey outranks email when both appear, and anything unfamiliar is
// "unknown" rather than an error: the claim is informational, not a gate.
func loginMethodFromAMR(amr []string) string {
	for _, method := range amr {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "webauthn", "passkey", "hwk":
			return "passkey"
		}
	}
	for _, method := range amr {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "email", "email_link", "magic_link", "otp":
			return "email"
		}
	}
	return "unknown"
}
