// Package accounts is the repository for who someone is and what they may do:
// users, their staff roles, and their browser sessions.
//
//portal:tables users staff_roles browser_sessions
package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the account tables. It holds no state; every method
// takes the connection to run on, so the same method serves a standalone call
// and a caller's open transaction.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// User is a person, as the portal knows them. Everything here comes from Pocket
// ID except the identifier and the passkey-prompt timestamp: the portal is not
// the system of record for names or email addresses.
type User struct {
	ID                       uuid.UUID
	PocketIDSub              string
	Email                    string
	DisplayName              string
	EmailVerified            bool
	PasskeyPromptDismissedAt *time.Time
}

// UpsertUser is the identity a completed sign-in asserts.
type UpsertUser struct {
	PocketIDSub   string
	Email         string
	DisplayName   string
	EmailVerified bool
	Now           time.Time
}

// UpsertBySubject creates or refreshes a user, keyed on the Pocket ID subject.
//
// The subject is the only stable link to the identity provider. Email is
// deliberately not a key: people change theirs, and treating it as an identifier
// would let a re-registered address inherit someone else's history.
func (r *Repo) UpsertBySubject(ctx context.Context, q db.Conn, in UpsertUser) (User, error) {
	if in.PocketIDSub == "" {
		return User{}, errors.New("accounts: a Pocket ID subject is required")
	}

	var u User
	err := q.QueryRow(ctx, `
		INSERT INTO users (id, pocket_id_sub, email, display_name, email_verified,
		                   created_at, updated_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $6)
		ON CONFLICT (pocket_id_sub) DO UPDATE SET
			email          = EXCLUDED.email,
			display_name   = EXCLUDED.display_name,
			email_verified = EXCLUDED.email_verified,
			updated_at     = EXCLUDED.updated_at,
			last_login_at  = EXCLUDED.last_login_at
		RETURNING id, pocket_id_sub, email, display_name, email_verified,
		          passkey_prompt_dismissed_at
	`, uuid.New(), in.PocketIDSub, in.Email, in.DisplayName, in.EmailVerified, in.Now).
		Scan(&u.ID, &u.PocketIDSub, &u.Email, &u.DisplayName, &u.EmailVerified,
			&u.PasskeyPromptDismissedAt)
	if err != nil {
		return User{}, fmt.Errorf("accounts: upsert user: %w", db.Normalize(err))
	}
	return u, nil
}

// ByID loads a user.
func (r *Repo) ByID(ctx context.Context, q db.Conn, id uuid.UUID) (User, error) {
	var u User
	err := q.QueryRow(ctx, `
		SELECT id, pocket_id_sub, email, display_name, email_verified,
		       passkey_prompt_dismissed_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.PocketIDSub, &u.Email, &u.DisplayName, &u.EmailVerified,
		&u.PasskeyPromptDismissedAt)
	if err != nil {
		return User{}, fmt.Errorf("accounts: load user: %w", db.Normalize(err))
	}
	return u, nil
}

// DismissPasskeyPrompt records that the member chose to skip setting up a
// passkey. A column rather than a cookie: it is a fact about a person, it
// survives a new browser, and the cookie form was silently rejected by every
// browser because a __Host- prefixed cookie cannot carry a non-root path.
func (r *Repo) DismissPasskeyPrompt(ctx context.Context, q db.Conn, userID uuid.UUID, now time.Time) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET passkey_prompt_dismissed_at = $2, updated_at = $2 WHERE id = $1`,
		userID, now)
	if err != nil {
		return fmt.Errorf("accounts: dismiss passkey prompt: %w", db.Normalize(err))
	}
	return nil
}

// GrantRole gives a user a staff role. Roles are `support`, `fulfillment` or
// `admin`; V1 grants only the latter two.
func (r *Repo) GrantRole(ctx context.Context, q db.Conn, userID uuid.UUID, role string, grantedBy *uuid.UUID, now time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO staff_roles (user_id, role, granted_by_user_id, granted_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role) DO UPDATE SET
			granted_by_user_id = EXCLUDED.granted_by_user_id,
			granted_at         = EXCLUDED.granted_at,
			revoked_at         = NULL
	`, userID, role, grantedBy, now)
	if err != nil {
		return fmt.Errorf("accounts: grant role: %w", db.Normalize(err))
	}
	return nil
}

// RevokeRole withdraws a staff role.
//
// Authorization is read from the database on every request, so a revoked role
// stops granting access immediately. The session itself survives, which is why
// the caller should also revoke sessions when removing someone's access for a
// security reason rather than a routine change.
func (r *Repo) RevokeRole(ctx context.Context, q db.Conn, userID uuid.UUID, role string, now time.Time) error {
	_, err := q.Exec(ctx,
		`UPDATE staff_roles SET revoked_at = $3 WHERE user_id = $1 AND role = $2 AND revoked_at IS NULL`,
		userID, role, now)
	if err != nil {
		return fmt.Errorf("accounts: revoke role: %w", db.Normalize(err))
	}
	return nil
}
