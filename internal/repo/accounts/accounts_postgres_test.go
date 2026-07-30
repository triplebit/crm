package accounts_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/testdb"
)

const (
	idleTTL     = 30 * time.Minute
	absoluteTTL = 12 * time.Hour
)

type fixture struct {
	repo *accounts.Repo
	pool *db.Pool
	ctx  context.Context
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{
		repo: accounts.New(),
		pool: testdb.Pool(t),
		ctx:  context.Background(),
		// Deliberately carries nanoseconds. PostgreSQL stores microseconds, so
		// any code that required a round-tripped timestamp to compare equal to
		// the original would fail here — which is exactly what broke every login
		// in the previous implementation, and what these tests must keep broken
		// if it ever returns.
		now: time.Now().UTC().Add(-time.Minute).Add(123456789 * time.Nanosecond),
	}
}

func (f *fixture) user(t *testing.T) accounts.User {
	t.Helper()
	sub := "sub-" + uuid.New().String()
	u, err := f.repo.UpsertBySubject(f.ctx, f.pool.Conn(), accounts.UpsertUser{
		PocketIDSub:   sub,
		Email:         sub + "@example.test",
		DisplayName:   "Test Member",
		EmailVerified: true,
		Now:           f.now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})
	return u
}

func (f *fixture) session(t *testing.T, userID uuid.UUID, mutate func(*accounts.Session)) accounts.Session {
	t.Helper()
	digest := sha256.Sum256([]byte(uuid.New().String()))
	s := accounts.Session{
		TokenDigest:       digest[:],
		UserID:            userID,
		CSRFCiphertext:    "v1.session-v1.envelope",
		LoginMethod:       "passkey",
		AuthenticatedAt:   f.now,
		CreatedAt:         f.now,
		LastSeenAt:        f.now,
		IdleExpiresAt:     f.now.Add(idleTTL),
		AbsoluteExpiresAt: f.now.Add(absoluteTTL),
	}
	if mutate != nil {
		mutate(&s)
	}
	if err := f.repo.CreateSession(f.ctx, f.pool.Conn(), s); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return s
}

// The milestone the previous implementation never reached: a session created,
// then successfully read back on the next request. It failed there because the
// decoder required a nanosecond-precision copy of a timestamp to equal the
// microsecond-precision value PostgreSQL returned.
func TestSessionCreatedIsReadableOnTheNextRequest(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	s := f.session(t, user.ID, nil)

	p, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, time.Now().UTC(), idleTTL)
	if err != nil {
		t.Fatalf("a session created moments ago could not be loaded: %v", err)
	}
	if p.User.ID != user.ID {
		t.Errorf("principal user = %v, want %v", p.User.ID, user.ID)
	}
	if p.User.Email != user.Email {
		t.Errorf("principal email = %q, want %q", p.User.Email, user.Email)
	}
	if p.Session.CSRFCiphertext != s.CSRFCiphertext {
		t.Error("the CSRF envelope did not survive the round trip")
	}
	if len(p.Roles) != 0 {
		t.Errorf("a member with no staff roles has roles %v", p.Roles)
	}
}

// A hundred consecutive sessions must all load. One would pass by luck even
// with the old precision bug present roughly one time in a thousand.
func TestEverySessionLoadsRegardlessOfSubsecondPrecision(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)

	for i := 0; i < 100; i++ {
		created := time.Now().UTC()
		digest := sha256.Sum256([]byte(uuid.New().String()))
		s := accounts.Session{
			TokenDigest:       digest[:],
			UserID:            user.ID,
			CSRFCiphertext:    "envelope",
			LoginMethod:       "email",
			AuthenticatedAt:   created,
			CreatedAt:         created,
			LastSeenAt:        created,
			IdleExpiresAt:     created.Add(idleTTL),
			AbsoluteExpiresAt: created.Add(absoluteTTL),
		}
		if err := f.repo.CreateSession(f.ctx, f.pool.Conn(), s); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, time.Now().UTC(), idleTTL); err != nil {
			t.Fatalf("session %d (created at %v) failed to load: %v", i, created, err)
		}
	}
}

func TestLoadAndTouchExtendsTheIdleWindow(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	s := f.session(t, user.ID, nil)

	later := time.Now().UTC()
	p, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, later, idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !p.Session.IdleExpiresAt.After(s.IdleExpiresAt) {
		t.Errorf("idle expiry did not move forward: %v then %v", s.IdleExpiresAt, p.Session.IdleExpiresAt)
	}
	// Extension must never push past the absolute deadline, or an active
	// session would live forever.
	if p.Session.IdleExpiresAt.After(p.Session.AbsoluteExpiresAt) {
		t.Error("idle expiry was extended beyond the absolute expiry")
	}
}

// Expiry is enforced by the statement itself, so there is no window in which
// application code could read an expired session and act on it.
func TestExpiredAndRevokedSessionsDoNotLoad(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	now := time.Now().UTC()

	t.Run("idle expired", func(t *testing.T) {
		s := f.session(t, user.ID, func(s *accounts.Session) {
			s.IdleExpiresAt = now.Add(-time.Second)
		})
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL); !errors.Is(err, db.ErrNotFound) {
			t.Errorf("an idle-expired session loaded: %v", err)
		}
	})

	t.Run("absolute expired", func(t *testing.T) {
		s := f.session(t, user.ID, func(s *accounts.Session) {
			s.AuthenticatedAt = now.Add(-24 * time.Hour)
			s.CreatedAt = now.Add(-24 * time.Hour)
			s.LastSeenAt = now.Add(-24 * time.Hour)
			s.IdleExpiresAt = now.Add(-13 * time.Hour)
			s.AbsoluteExpiresAt = now.Add(-12 * time.Hour)
		})
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL); !errors.Is(err, db.ErrNotFound) {
			t.Errorf("an absolutely-expired session loaded: %v", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		s := f.session(t, user.ID, nil)
		if err := f.repo.Revoke(f.ctx, f.pool.Conn(), s.TokenDigest, "signed out", now); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL); !errors.Is(err, db.ErrNotFound) {
			t.Errorf("a revoked session loaded: %v", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		unknown := sha256.Sum256([]byte("never issued"))
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), unknown[:], now, idleTTL); !errors.Is(err, db.ErrNotFound) {
			t.Errorf("an unknown token loaded: %v", err)
		}
	})
}

// The force-logout path, which previously existed as a function with no caller.
func TestRevokeUserEndsEverySessionForThatPerson(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	other := f.user(t)

	var mine [][]byte
	for i := 0; i < 3; i++ {
		mine = append(mine, f.session(t, user.ID, nil).TokenDigest)
	}
	theirs := f.session(t, other.ID, nil)

	now := time.Now().UTC()
	count, err := f.repo.RevokeUser(f.ctx, f.pool.Conn(), user.ID, "security event", now)
	if err != nil {
		t.Fatalf("revoke user: %v", err)
	}
	if count != 3 {
		t.Errorf("revoked %d sessions, want 3", count)
	}
	for i, digest := range mine {
		if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), digest, now, idleTTL); !errors.Is(err, db.ErrNotFound) {
			t.Errorf("session %d survived a force logout: %v", i, err)
		}
	}
	if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), theirs.TokenDigest, now, idleTTL); err != nil {
		t.Errorf("another person's session was revoked too: %v", err)
	}
}

// Authorization is re-read on every request, so withdrawing a role takes effect
// on the next one rather than whenever a credential happens to expire.
func TestRolesAreReadFreshOnEveryLoad(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	s := f.session(t, user.ID, nil)
	now := time.Now().UTC()

	if err := f.repo.GrantRole(f.ctx, f.pool.Conn(), user.ID, "fulfillment", nil, now); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := f.repo.GrantRole(f.ctx, f.pool.Conn(), user.ID, "admin", nil, now); err != nil {
		t.Fatalf("grant: %v", err)
	}

	p, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(p.Roles) != 2 || !p.HasRole("admin") || !p.HasRole("fulfillment") {
		t.Fatalf("roles = %v, want admin and fulfillment", p.Roles)
	}

	if err := f.repo.RevokeRole(f.ctx, f.pool.Conn(), user.ID, "admin", now); err != nil {
		t.Fatalf("revoke role: %v", err)
	}
	p, err = f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.HasRole("admin") {
		t.Error("a revoked role was still granted on the very next request")
	}
	if !p.HasRole("fulfillment") {
		t.Error("revoking one role removed another")
	}
}

// The subject is the only stable link to the identity provider, so signing in
// again must refresh the same person rather than create a second one.
func TestSigningInAgainRefreshesTheSameUser(t *testing.T) {
	f := newFixture(t)
	sub := "sub-" + uuid.New().String()

	first, err := f.repo.UpsertBySubject(f.ctx, f.pool.Conn(), accounts.UpsertUser{
		PocketIDSub: sub, Email: "before@example.test", DisplayName: "Before",
		EmailVerified: true, Now: f.now,
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, first.ID)
	})

	second, err := f.repo.UpsertBySubject(f.ctx, f.pool.Conn(), accounts.UpsertUser{
		PocketIDSub: sub, Email: "after@example.test", DisplayName: "After",
		EmailVerified: true, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("a second sign-in created a new user: %v then %v", first.ID, second.ID)
	}
	if second.Email != "after@example.test" || second.DisplayName != "After" {
		t.Error("the identity provider's current details were not applied")
	}
}

func TestDeleteExpiredRemovesOnlyUnusableSessions(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	now := time.Now().UTC()

	live := f.session(t, user.ID, nil)
	expired := f.session(t, user.ID, func(s *accounts.Session) {
		s.AuthenticatedAt = now.Add(-48 * time.Hour)
		s.CreatedAt = now.Add(-48 * time.Hour)
		s.LastSeenAt = now.Add(-48 * time.Hour)
		s.IdleExpiresAt = now.Add(-40 * time.Hour)
		s.AbsoluteExpiresAt = now.Add(-36 * time.Hour)
	})

	removed, err := f.repo.DeleteExpired(f.ctx, f.pool.Conn(), now, 100)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if removed < 1 {
		t.Error("no expired session was removed")
	}

	if _, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), live.TokenDigest, now, idleTTL); err != nil {
		t.Errorf("a live session was deleted: %v", err)
	}
	var stillThere int
	if err := f.pool.Conn().QueryRow(f.ctx,
		`SELECT count(*) FROM browser_sessions WHERE token_hash = $1`, expired.TokenDigest).Scan(&stillThere); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stillThere != 0 {
		t.Error("the expired session was not deleted")
	}
}

func TestDismissingThePasskeyPromptIsRememberedAcrossSessions(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	s := f.session(t, user.ID, nil)
	now := time.Now().UTC()

	p, err := f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), s.TokenDigest, now, idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.User.PasskeyPromptDismissedAt != nil {
		t.Fatal("the prompt was already dismissed")
	}

	if err := f.repo.DismissPasskeyPrompt(f.ctx, f.pool.Conn(), user.ID, now); err != nil {
		t.Fatalf("dismiss: %v", err)
	}

	// A different session, i.e. a different browser: the dismissal is a fact
	// about the person, not about one cookie jar.
	other := f.session(t, user.ID, nil)
	p, err = f.repo.LoadAndTouch(f.ctx, f.pool.Conn(), other.TokenDigest, now, idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.User.PasskeyPromptDismissedAt == nil {
		t.Error("the dismissal did not carry to another browser")
	}
}

// countingConn wraps a connection and counts statements, so the round-trip
// claim below is verified rather than asserted in a comment.
type countingConn struct {
	inner db.Conn
	n     int
}

func (c *countingConn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.n++
	return c.inner.Exec(ctx, sql, args...)
}

func (c *countingConn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	c.n++
	return c.inner.Query(ctx, sql, args...)
}

func (c *countingConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	c.n++
	return c.inner.QueryRow(ctx, sql, args...)
}

// Loading a principal must cost exactly one statement.
//
// The previous implementation made four sequential round trips on every
// authenticated request: touch the session, look the user up by subject, read
// staff roles, then read group projections. No caching, no join. That cost was
// paid on every page view by every signed-in person.
func TestLoadingAPrincipalCostsOneRoundTrip(t *testing.T) {
	f := newFixture(t)
	user := f.user(t)
	s := f.session(t, user.ID, nil)
	if err := f.repo.GrantRole(f.ctx, f.pool.Conn(), user.ID, "fulfillment", nil, time.Now().UTC()); err != nil {
		t.Fatalf("grant: %v", err)
	}

	counter := &countingConn{inner: f.pool.Conn()}
	p, err := f.repo.LoadAndTouch(f.ctx, counter, s.TokenDigest, time.Now().UTC(), idleTTL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if counter.n != 1 {
		t.Errorf("loading a principal took %d statements, want 1", counter.n)
	}
	// And it really did return everything, so the count is not low because the
	// work was skipped.
	if p.User.Email == "" || !p.HasRole("fulfillment") || p.Session.CSRFCiphertext == "" {
		t.Error("one statement did not return the session, the user and the roles")
	}
}
