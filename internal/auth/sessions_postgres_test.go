package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/csrf"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/testdb"
)

func newSessions(t *testing.T) (*auth.Sessions, *accounts.Repo, uuid.UUID) {
	t.Helper()
	pool := testdb.Pool(t)
	repo := accounts.New()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ring, err := cryptox.NewKeyring("session-v1", map[string][]byte{"session-v1": key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	sessions, err := auth.NewSessions(auth.SessionOptions{
		Repo: repo, Pool: pool, Keys: ring,
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}

	sub := "sub-" + uuid.New().String()
	user, err := repo.UpsertBySubject(context.Background(), pool.Conn(), accounts.UpsertUser{
		PocketIDSub: sub, Email: sub + "@example.test", DisplayName: "Member",
		EmailVerified: true, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	})
	return sessions, repo, user.ID
}

// The end-to-end version of the milestone the previous implementation never
// reached: issue a session, then load it back the way the next request would.
func TestIssuedSessionLoadsBack(t *testing.T) {
	ctx := context.Background()
	sessions, _, userID := newSessions(t)

	token, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	p, err := sessions.Load(ctx, token.String())
	if err != nil {
		t.Fatalf("a session issued moments ago did not load: %v", err)
	}
	if p.User.ID != userID {
		t.Errorf("principal user = %v, want %v", p.User.ID, userID)
	}
	if len(p.CSRFSecret) != csrf.SecretSize {
		t.Errorf("CSRF secret is %d bytes, want %d", len(p.CSRFSecret), csrf.SecretSize)
	}

	// The secret must actually work, not merely be the right length.
	tok, err := csrf.Token(p.CSRFSecret)
	if err != nil {
		t.Fatalf("derive CSRF token: %v", err)
	}
	if err := csrf.Validate(p.CSRFSecret, tok); err != nil {
		t.Errorf("the session's CSRF secret does not validate its own token: %v", err)
	}
}

// Fifty consecutive issue-and-load cycles. The previous implementation's bug
// let roughly one in a thousand succeed, so a single round trip proves little.
func TestEveryIssuedSessionLoadsBack(t *testing.T) {
	ctx := context.Background()
	sessions, _, userID := newSessions(t)

	for i := 0; i < 50; i++ {
		token, err := sessions.Issue(ctx, userID, "email")
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if _, err := sessions.Load(ctx, token.String()); err != nil {
			t.Fatalf("session %d did not load: %v", i, err)
		}
	}
}

// Every rejection is the same error, so probing cannot distinguish "no such
// token" from "expired" from "revoked".
func TestUnusableSessionsAllReportTheSameError(t *testing.T) {
	ctx := context.Background()
	sessions, _, userID := newSessions(t)

	valid, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	revoked, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := sessions.Revoke(ctx, revoked.String(), "signed out"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for name, raw := range map[string]string{
		"empty":            "",
		"not base64":       "!!!!",
		"wrong length":     "abcd",
		"never issued":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"revoked":          revoked.String(),
		"valid but padded": valid.String() + "=",
	} {
		if _, err := sessions.Load(ctx, raw); !errors.Is(err, auth.ErrNoSession) {
			t.Errorf("Load(%s) error = %v, want ErrNoSession", name, err)
		}
	}
}

// The envelope's associated data binds it to one row, so a ciphertext copied
// from another session must fail to open rather than yield its CSRF secret.
func TestEnvelopeCannotBeMovedBetweenSessions(t *testing.T) {
	ctx := context.Background()
	sessions, repo, userID := newSessions(t)
	pool := testdb.Pool(t)

	victim, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	attacker, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var victimEnvelope string
	if err := pool.Conn().QueryRow(ctx,
		`SELECT csrf_ciphertext FROM browser_sessions WHERE token_hash = $1`,
		victim.Digest()).Scan(&victimEnvelope); err != nil {
		t.Fatalf("read envelope: %v", err)
	}

	// Transplant the victim's sealed secret onto the attacker's row.
	if _, err := pool.Conn().Exec(ctx,
		`UPDATE browser_sessions SET csrf_ciphertext = $2 WHERE token_hash = $1`,
		attacker.Digest(), victimEnvelope); err != nil {
		t.Fatalf("transplant envelope: %v", err)
	}

	if _, err := sessions.Load(ctx, attacker.String()); !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("a transplanted envelope was accepted: %v", err)
	}
	// The victim's own session is untouched.
	if _, err := sessions.Load(ctx, victim.String()); err != nil {
		t.Errorf("the victim's session broke: %v", err)
	}
	_ = repo
}

// Each session gets its own secret, so a token minted for one cannot be
// replayed against another.
func TestEachSessionHasItsOwnCSRFSecret(t *testing.T) {
	ctx := context.Background()
	sessions, _, userID := newSessions(t)

	first, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	second, err := sessions.Issue(ctx, userID, "passkey")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	a, err := sessions.Load(ctx, first.String())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b, err := sessions.Load(ctx, second.String())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(a.CSRFSecret) == string(b.CSRFSecret) {
		t.Fatal("two sessions share a CSRF secret")
	}

	tokenForA, err := csrf.Token(a.CSRFSecret)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := csrf.Validate(b.CSRFSecret, tokenForA); err == nil {
		t.Error("one session's CSRF token validated against another's secret")
	}
}

func TestRevokeUserEndsEverySession(t *testing.T) {
	ctx := context.Background()
	sessions, _, userID := newSessions(t)

	var issued []string
	for i := 0; i < 3; i++ {
		token, err := sessions.Issue(ctx, userID, "passkey")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		issued = append(issued, token.String())
	}

	count, err := sessions.RevokeUser(ctx, userID, "security event")
	if err != nil {
		t.Fatalf("revoke user: %v", err)
	}
	if count != 3 {
		t.Errorf("revoked %d sessions, want 3", count)
	}
	for i, raw := range issued {
		if _, err := sessions.Load(ctx, raw); !errors.Is(err, auth.ErrNoSession) {
			t.Errorf("session %d survived: %v", i, err)
		}
	}
}

// Signing out must always succeed, even with a nonsense cookie, or a person
// with a corrupted cookie could never clear it.
func TestRevokeToleratesUnusableTokens(t *testing.T) {
	ctx := context.Background()
	sessions, _, _ := newSessions(t)

	for _, raw := range []string{"", "!!!", "AAAA"} {
		if err := sessions.Revoke(ctx, raw, "signed out"); err != nil {
			t.Errorf("Revoke(%q) = %v, want nil", raw, err)
		}
	}
}

// An incomplete manager must fail at construction. The previous implementation
// silently substituted an in-memory backend when no database was supplied,
// which is why its unit tests passed while its only real backend was broken.
func TestIncompleteConfigurationIsRefused(t *testing.T) {
	pool := testdb.Pool(t)
	repo := accounts.New()
	key := make([]byte, 32)
	key[0] = 1
	ring, err := cryptox.NewKeyring("s", map[string][]byte{"s": key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	full := auth.SessionOptions{
		Repo: repo, Pool: pool, Keys: ring,
		IdleTTL: time.Minute, AbsoluteTTL: time.Hour,
	}

	for name, mutate := range map[string]func(*auth.SessionOptions){
		"no repo":          func(o *auth.SessionOptions) { o.Repo = nil },
		"no pool":          func(o *auth.SessionOptions) { o.Pool = nil },
		"no keys":          func(o *auth.SessionOptions) { o.Keys = nil },
		"no idle TTL":      func(o *auth.SessionOptions) { o.IdleTTL = 0 },
		"no absolute TTL":  func(o *auth.SessionOptions) { o.AbsoluteTTL = 0 },
		"idle beyond abs":  func(o *auth.SessionOptions) { o.IdleTTL = 2 * time.Hour },
		"negative idleTTL": func(o *auth.SessionOptions) { o.IdleTTL = -time.Minute },
	} {
		opts := full
		mutate(&opts)
		if _, err := auth.NewSessions(opts); err == nil {
			t.Errorf("NewSessions accepted a configuration with %s", name)
		}
	}
}
