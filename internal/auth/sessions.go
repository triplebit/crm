// Package auth turns a Pocket ID sign-in into a portal session, and a session
// cookie back into the person making a request.
package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/csrf"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/tokens"
)

// ErrNoSession means the request carried no usable session. It is deliberately
// one error for every cause — absent, malformed, unknown, expired, revoked —
// because distinguishing them for the caller would distinguish them for an
// attacker probing for valid tokens.
var ErrNoSession = errors.New("auth: no valid session")

// Principal is who is making a request, plus the CSRF secret for their session.
type Principal struct {
	User  accounts.User
	Roles []string

	// LoginMethod is how this session was authenticated: passkey, email or
	// unknown. Display only; it grants nothing.
	LoginMethod string

	// CSRFSecret is the decrypted per-session secret. It never leaves the
	// server and is never rendered; the derived token is what reaches a page.
	CSRFSecret []byte

	sessionDigest []byte
}

// HasRole reports whether the principal currently holds a staff role.
func (p Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Sessions issues and validates browser sessions.
type Sessions struct {
	repo        *accounts.Repo
	pool        *db.Pool
	keys        *cryptox.Keyring
	idleTTL     time.Duration
	absoluteTTL time.Duration
	now         func() time.Time
}

// SessionOptions configures the manager. Every field is required except now,
// which defaults to time.Now — there is no fallback that silently substitutes
// an in-memory backend, which is what allowed the previous implementation's
// unit tests to pass while its only real backend was broken.
type SessionOptions struct {
	Repo        *accounts.Repo
	Pool        *db.Pool
	Keys        *cryptox.Keyring
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	Now         func() time.Time
}

// NewSessions builds a session manager, refusing an incomplete configuration.
func NewSessions(opts SessionOptions) (*Sessions, error) {
	switch {
	case opts.Repo == nil:
		return nil, errors.New("auth: an accounts repository is required")
	case opts.Pool == nil:
		return nil, errors.New("auth: a database pool is required")
	case opts.Keys == nil:
		return nil, errors.New("auth: a session keyring is required")
	case opts.IdleTTL <= 0:
		return nil, errors.New("auth: a positive idle TTL is required")
	case opts.AbsoluteTTL <= 0:
		return nil, errors.New("auth: a positive absolute TTL is required")
	case opts.IdleTTL > opts.AbsoluteTTL:
		return nil, errors.New("auth: the idle TTL must not exceed the absolute TTL")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Sessions{
		repo:        opts.Repo,
		pool:        opts.Pool,
		keys:        opts.Keys,
		idleTTL:     opts.IdleTTL,
		absoluteTTL: opts.AbsoluteTTL,
		now:         now,
	}, nil
}

// Issue creates a session and returns the token for the browser.
//
// The token is returned once and never stored: only its digest is written. The
// caller must place it in a cookie and then forget it.
func (s *Sessions) Issue(ctx context.Context, userID uuid.UUID, loginMethod string) (tokens.Token, error) {
	token, err := tokens.New(nil)
	if err != nil {
		return tokens.Token{}, err
	}
	secret, err := csrf.NewSecret(nil)
	if err != nil {
		return tokens.Token{}, err
	}

	digest := token.Digest()
	envelope, err := s.keys.Encrypt(secret, sessionAAD(digest))
	if err != nil {
		return tokens.Token{}, fmt.Errorf("auth: seal session: %w", err)
	}

	now := s.now().UTC()
	record := accounts.Session{
		TokenDigest:       digest,
		UserID:            userID,
		CSRFCiphertext:    envelope,
		LoginMethod:       normalizeLoginMethod(loginMethod),
		AuthenticatedAt:   now,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(s.idleTTL),
		AbsoluteExpiresAt: now.Add(s.absoluteTTL),
	}
	if err := s.repo.CreateSession(ctx, s.pool.Conn(), record); err != nil {
		return tokens.Token{}, err
	}
	return token, nil
}

// Load resolves a raw cookie value into a principal, extending the idle window.
func (s *Sessions) Load(ctx context.Context, raw string) (Principal, error) {
	token, err := tokens.Parse(raw)
	if err != nil {
		return Principal{}, ErrNoSession
	}
	digest := token.Digest()

	p, err := s.repo.LoadAndTouch(ctx, s.pool.Conn(), digest, s.now().UTC(), s.idleTTL)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return Principal{}, ErrNoSession
		}
		// A database failure must not read as "signed out": that would silently
		// downgrade every request to anonymous during an outage. The caller is
		// expected to fail closed on anything that is not ErrNoSession.
		return Principal{}, err
	}

	// The associated data binds this envelope to this row's token digest, so a
	// ciphertext copied from another session fails to open. That binding is the
	// tamper protection; the previous implementation added a second, redundant
	// check comparing duplicated timestamps, and it was the redundant one that
	// broke every login.
	secret, err := s.keys.Decrypt(p.Session.CSRFCiphertext, sessionAAD(digest))
	if err != nil {
		return Principal{}, ErrNoSession
	}

	return Principal{
		User:          p.User,
		Roles:         p.Roles,
		LoginMethod:   p.Session.LoginMethod,
		CSRFSecret:    secret,
		sessionDigest: digest,
	}, nil
}

// Revoke ends the session identified by a raw cookie value. Unknown or
// malformed values are not an error: signing out must always succeed.
func (s *Sessions) Revoke(ctx context.Context, raw, reason string) error {
	token, err := tokens.Parse(raw)
	if err != nil {
		return nil
	}
	return s.repo.Revoke(ctx, s.pool.Conn(), token.Digest(), reason, s.now().UTC())
}

// RevokeUser ends every live session for one person, and reports how many.
func (s *Sessions) RevokeUser(ctx context.Context, userID uuid.UUID, reason string) (int64, error) {
	return s.repo.RevokeUser(ctx, s.pool.Conn(), userID, reason, s.now().UTC())
}

// NeedsRotation reports whether a principal's envelope was sealed with a
// retired key, so a sweep can re-seal it under the active one.
func (s *Sessions) NeedsRotation(envelope string) bool { return s.keys.NeedsRotation(envelope) }

// sessionAAD binds an envelope to one session row.
//
// Including the token digest means a ciphertext lifted from another row cannot
// be opened here, so a swapped envelope fails authentication rather than
// yielding someone else's CSRF secret.
func sessionAAD(digest []byte) []byte {
	return []byte("triplebit-session:v1\x00" + hex.EncodeToString(digest))
}

// normalizeLoginMethod maps an OIDC amr claim onto the values the schema
// permits, defaulting to "unknown" rather than rejecting an unfamiliar one.
func normalizeLoginMethod(method string) string {
	switch method {
	case "passkey", "email":
		return method
	default:
		return "unknown"
	}
}
