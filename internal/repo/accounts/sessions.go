package accounts

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
)

// Session is one browser session. It is identified by the SHA-256 digest of the
// opaque token the browser holds; the token itself is never stored.
//
// Every timestamp lives here and nowhere else. The encrypted CSRF envelope
// carries no copy of them, because requiring two representations of one fact to
// agree is what broke every login in the previous implementation.
type Session struct {
	TokenDigest       []byte
	UserID            uuid.UUID
	CSRFCiphertext    string
	LoginMethod       string
	AuthenticatedAt   time.Time
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// Principal is everything a request needs to know about who is making it:
// the live session, the person, and the staff roles they hold right now.
//
// It is produced by one statement. The previous implementation performed four
// sequential round trips on every authenticated request — touch the session,
// look the user up by subject, read staff roles, read group projections — with
// no caching and no join.
type Principal struct {
	Session Session
	User    User
	Roles   []string
}

// HasRole reports whether the principal currently holds a role.
func (p Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// CreateSession stores a new session.
func (r *Repo) CreateSession(ctx context.Context, q db.Conn, s Session) error {
	_, err := q.Exec(ctx, `
		INSERT INTO browser_sessions (
			token_hash, user_id, csrf_ciphertext, login_method,
			authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, s.TokenDigest, s.UserID, s.CSRFCiphertext, s.LoginMethod,
		s.AuthenticatedAt, s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt, s.AbsoluteExpiresAt)
	if err != nil {
		return fmt.Errorf("accounts: create session: %w", db.Normalize(err))
	}
	return nil
}

// LoadAndTouch validates a session and extends its idle window, returning the
// principal, in one round trip.
//
// Expiry is enforced in the WHERE clause rather than in Go. A session that has
// passed either deadline, or has been revoked, simply does not match, so there
// is no window in which application code could read an expired session and act
// on it. It also means the idle extension and the validity check cannot
// disagree: they are the same statement.
//
// Roles are re-read here, on every request, and never carried in a token or a
// cookie. Withdrawing a role therefore takes effect on the person's next
// request rather than whenever their credential happens to expire.
func (r *Repo) LoadAndTouch(
	ctx context.Context,
	q db.Conn,
	tokenDigest []byte,
	now time.Time,
	idleTTL time.Duration,
) (Principal, error) {
	var p Principal
	err := q.QueryRow(ctx, `
		WITH touched AS (
			UPDATE browser_sessions
			SET last_seen_at    = $2,
			    idle_expires_at = LEAST($2::timestamptz + $3::interval, absolute_expires_at)
			WHERE token_hash = $1
			  AND revoked_at IS NULL
			  AND absolute_expires_at > $2
			  AND idle_expires_at     > $2
			RETURNING token_hash, user_id, csrf_ciphertext, login_method,
			          authenticated_at, created_at, last_seen_at,
			          idle_expires_at, absolute_expires_at
		)
		SELECT t.token_hash, t.user_id, t.csrf_ciphertext, t.login_method,
		       t.authenticated_at, t.created_at, t.last_seen_at,
		       t.idle_expires_at, t.absolute_expires_at,
		       u.pocket_id_sub, u.email, u.display_name, u.email_verified,
		       u.passkey_prompt_dismissed_at,
		       COALESCE(
		           array_agg(sr.role ORDER BY sr.role) FILTER (WHERE sr.role IS NOT NULL),
		           ARRAY[]::text[]
		       ) AS roles
		FROM touched t
		JOIN users u ON u.id = t.user_id
		LEFT JOIN staff_roles sr
		       ON sr.user_id = t.user_id AND sr.revoked_at IS NULL
		GROUP BY t.token_hash, t.user_id, t.csrf_ciphertext, t.login_method,
		         t.authenticated_at, t.created_at, t.last_seen_at,
		         t.idle_expires_at, t.absolute_expires_at,
		         u.id, u.pocket_id_sub, u.email, u.display_name, u.email_verified,
		         u.passkey_prompt_dismissed_at
	`, tokenDigest, now, idleTTL).Scan(
		&p.Session.TokenDigest, &p.Session.UserID, &p.Session.CSRFCiphertext,
		&p.Session.LoginMethod, &p.Session.AuthenticatedAt, &p.Session.CreatedAt,
		&p.Session.LastSeenAt, &p.Session.IdleExpiresAt, &p.Session.AbsoluteExpiresAt,
		&p.User.PocketIDSub, &p.User.Email, &p.User.DisplayName, &p.User.EmailVerified,
		&p.User.PasskeyPromptDismissedAt,
		&p.Roles,
	)
	if err != nil {
		return Principal{}, fmt.Errorf("accounts: load session: %w", db.Normalize(err))
	}
	p.User.ID = p.Session.UserID
	return p, nil
}

// Revoke ends one session immediately. Used by sign-out, and by sign-in to
// retire the previous session before issuing a new one.
func (r *Repo) Revoke(ctx context.Context, q db.Conn, tokenDigest []byte, reason string, now time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE browser_sessions
		SET revoked_at = $2, revoked_reason = $3
		WHERE token_hash = $1 AND revoked_at IS NULL
	`, tokenDigest, now, reason)
	if err != nil {
		return fmt.Errorf("accounts: revoke session: %w", db.Normalize(err))
	}
	return nil
}

// RevokeUser ends every live session belonging to one person, and reports how
// many it ended.
//
// This is the force-logout path. The previous implementation had an equivalent
// function with no callers anywhere, which meant that in practice there was no
// way to sign someone out of every browser after a security event. Staff-role
// revocation (M7) and erasure (M8) must call this when they arrive; until they
// do, its callers are its tests, and this comment is the reminder that a
// security control without a caller is the exact failure being rebuilt away.
func (r *Repo) RevokeUser(ctx context.Context, q db.Conn, userID uuid.UUID, reason string, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE browser_sessions
		SET revoked_at = $2, revoked_reason = $3
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID, now, reason)
	if err != nil {
		return 0, fmt.Errorf("accounts: revoke sessions for user: %w", db.Normalize(err))
	}
	return tag.RowsAffected(), nil
}

// DeleteExpired removes sessions that can no longer be used, and reports how
// many it removed.
//
// Retention, not tidiness. Previously nothing ever deleted a session row, so
// every envelope written since deployment accumulated indefinitely — and each
// one held an email address, which is why it was a privacy finding rather than
// a disk-space one. The envelope now holds only random bytes, but expired rows
// still carry timestamps and a user reference, and there is no reason to keep
// them.
func (r *Repo) DeleteExpired(ctx context.Context, q db.Conn, olderThan time.Time, limit int) (int64, error) {
	tag, err := q.Exec(ctx, `
		DELETE FROM browser_sessions
		WHERE token_hash IN (
			SELECT token_hash FROM browser_sessions
			WHERE absolute_expires_at <= $1
			   OR (revoked_at IS NOT NULL AND revoked_at <= $1)
			LIMIT $2
		)
	`, olderThan, limit)
	if err != nil {
		return 0, fmt.Errorf("accounts: delete expired sessions: %w", db.Normalize(err))
	}
	return tag.RowsAffected(), nil
}
