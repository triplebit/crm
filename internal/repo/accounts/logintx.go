package accounts

import (
	"context"
	"fmt"
	"time"

	"triplebit.org/portal/internal/db"
)

// LoginTransaction is the server-side state of one in-flight OIDC sign-in:
// written when the member is redirected to Pocket ID, consumed exactly once
// when the callback returns. The browser holds only an opaque token; state,
// nonce and the PKCE verifier never leave the server.
type LoginTransaction struct {
	TokenDigest  []byte
	State        string
	Nonce        string
	PKCEVerifier string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// CreateLoginTransaction stores a new sign-in attempt.
func (r *Repo) CreateLoginTransaction(ctx context.Context, q db.Conn, tx LoginTransaction) error {
	_, err := q.Exec(ctx, `
		INSERT INTO login_transactions (
			token_hash, state, nonce, pkce_verifier, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, tx.TokenDigest, tx.State, tx.Nonce, tx.PKCEVerifier, tx.CreatedAt, tx.ExpiresAt)
	if err != nil {
		return fmt.Errorf("accounts: create login transaction: %w", db.Normalize(err))
	}
	return nil
}

// ConsumeLoginTransaction atomically deletes and returns a live sign-in
// attempt. An expired or already-consumed transaction returns db.ErrNotFound.
//
// Single use is what DELETE ... RETURNING buys: two callbacks racing on the
// same token cannot both succeed, because only one of them deletes the row.
func (r *Repo) ConsumeLoginTransaction(ctx context.Context, q db.Conn, tokenDigest []byte, now time.Time) (LoginTransaction, error) {
	var tx LoginTransaction
	err := q.QueryRow(ctx, `
		DELETE FROM login_transactions
		WHERE token_hash = $1 AND expires_at > $2
		RETURNING token_hash, state, nonce, pkce_verifier, created_at, expires_at
	`, tokenDigest, now).Scan(
		&tx.TokenDigest, &tx.State, &tx.Nonce, &tx.PKCEVerifier,
		&tx.CreatedAt, &tx.ExpiresAt,
	)
	if err != nil {
		return LoginTransaction{}, fmt.Errorf("accounts: consume login transaction: %w", db.Normalize(err))
	}
	return tx, nil
}

// DeleteExpiredLoginTransactions sweeps abandoned sign-in attempts — closed
// tabs, failed IdP logins — and reports how many it removed.
func (r *Repo) DeleteExpiredLoginTransactions(ctx context.Context, q db.Conn, olderThan time.Time, limit int) (int64, error) {
	tag, err := q.Exec(ctx, `
		DELETE FROM login_transactions
		WHERE token_hash IN (
			SELECT token_hash FROM login_transactions
			WHERE expires_at <= $1
			LIMIT $2
		)
	`, olderThan, limit)
	if err != nil {
		return 0, fmt.Errorf("accounts: delete expired login transactions: %w", db.Normalize(err))
	}
	return tag.RowsAffected(), nil
}
