package accounts_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/accounts"
)

func (f *fixture) loginTx(t *testing.T, mutate func(*accounts.LoginTransaction)) accounts.LoginTransaction {
	t.Helper()
	digest := sha256.Sum256([]byte(uuid.New().String()))
	tx := accounts.LoginTransaction{
		TokenDigest:  digest[:],
		State:        "state-" + uuid.New().String(),
		Nonce:        "nonce-" + uuid.New().String(),
		PKCEVerifier: "verifier-" + uuid.New().String(),
		CreatedAt:    f.now,
		ExpiresAt:    f.now.Add(10 * time.Minute),
	}
	if mutate != nil {
		mutate(&tx)
	}
	if err := f.repo.CreateLoginTransaction(f.ctx, f.pool.Conn(), tx); err != nil {
		t.Fatalf("create login transaction: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM login_transactions WHERE token_hash = $1`, tx.TokenDigest)
	})
	return tx
}

func TestLoginTransactionIsSingleUse(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	created := f.loginTx(t, nil)

	got, err := f.repo.ConsumeLoginTransaction(f.ctx, f.pool.Conn(), created.TokenDigest, f.now)
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if got.State != created.State || got.Nonce != created.Nonce || got.PKCEVerifier != created.PKCEVerifier {
		t.Errorf("consumed transaction does not match what was stored: %+v vs %+v", got, created)
	}

	// The second consume must fail: DELETE ... RETURNING removed the row, so a
	// replayed callback has nothing to match.
	if _, err := f.repo.ConsumeLoginTransaction(f.ctx, f.pool.Conn(), created.TokenDigest, f.now); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("second consume: got %v, want db.ErrNotFound — a login transaction must be single-use", err)
	}
}

func TestExpiredLoginTransactionCannotBeConsumed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	created := f.loginTx(t, nil)

	after := created.ExpiresAt.Add(time.Second)
	if _, err := f.repo.ConsumeLoginTransaction(f.ctx, f.pool.Conn(), created.TokenDigest, after); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("consume after expiry: got %v, want db.ErrNotFound", err)
	}

	// Expiry is enforced in the WHERE clause, so the row itself must still
	// exist for the sweeper — being unusable and being deleted are different
	// facts.
	var remaining int
	if err := f.pool.Conn().QueryRow(f.ctx,
		`SELECT count(*) FROM login_transactions WHERE token_hash = $1`,
		created.TokenDigest).Scan(&remaining); err != nil {
		t.Fatalf("count login transactions: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expired transaction row count = %d, want 1 until the sweeper removes it", remaining)
	}
}

func TestDeleteExpiredLoginTransactionsSweepsOnlyTheDead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dead := f.loginTx(t, func(tx *accounts.LoginTransaction) {
		tx.CreatedAt = f.now.Add(-time.Hour)
		tx.ExpiresAt = f.now.Add(-50 * time.Minute)
	})
	live := f.loginTx(t, nil)

	// Other tests run in parallel against the same table, so assert on these
	// two rows rather than on the returned count.
	if _, err := f.repo.DeleteExpiredLoginTransactions(f.ctx, f.pool.Conn(), f.now, 1000); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	var count int
	if err := f.pool.Conn().QueryRow(f.ctx,
		`SELECT count(*) FROM login_transactions WHERE token_hash = $1`,
		dead.TokenDigest).Scan(&count); err != nil {
		t.Fatalf("count dead: %v", err)
	}
	if count != 0 {
		t.Error("the expired transaction survived the sweep")
	}
	if _, err := f.repo.ConsumeLoginTransaction(f.ctx, f.pool.Conn(), live.TokenDigest, f.now); err != nil {
		t.Errorf("the live transaction was swept: %v", err)
	}
}
