package db

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TxOptions selects the isolation level, the retry policy and an optional
// advisory lock for one transaction.
//
// The zero value — read committed, no retry, no lock — is the right choice for
// most work, so the common call reads WithTx(ctx, db.TxOptions{}, fn).
type TxOptions struct {
	// Serializable runs at pgx.Serializable instead of read committed. Use it
	// where correctness depends on a predicate still being true at commit, such
	// as "this member has no other in-flight membership order".
	Serializable bool

	// Retries is how many times a transaction that failed with a serialization
	// or deadlock error may be retried. Anything Serializable should set it:
	// a serialization failure is the expected, correct outcome of two clients
	// racing, not an error to surface. The previous implementation opened
	// exactly one Serializable transaction, for order creation, and had no
	// retry loop anywhere, so two people enrolling at the same moment produced
	// a 500 for one of them.
	Retries int

	// Lock, when non-empty, takes a transaction-scoped advisory lock on
	// hashtextextended(Lock, 0) before fn runs, serializing every transaction
	// that names the same string. Used to serialize per-actor Stripe Customer
	// creation, where two concurrent requests must not produce two Customers.
	Lock string
}

// WithTx runs fn inside a single transaction and commits if it returns nil.
//
// CONTRACT: fn must be a pure database function. It must not call Stripe, sleep,
// send mail, or mutate anything outside the transaction, BECAUSE FN CAN BE
// INVOKED MORE THAN ONCE. Work that must happen exactly once goes outside, in
// the service, typically as: commit an intent, do the remote call, commit the
// result.
func (p *Pool) WithTx(ctx context.Context, opts TxOptions, fn func(Conn) error) error {
	iso := pgx.ReadCommitted
	if opts.Serializable {
		iso = pgx.Serializable
	}

	for attempt := 0; ; attempt++ {
		err := p.runOnce(ctx, iso, opts.Lock, fn)
		if err == nil {
			return nil
		}
		if attempt < opts.Retries && IsRetryable(err) {
			if waitErr := backoff(ctx, attempt); waitErr != nil {
				return waitErr
			}
			continue
		}
		return Normalize(err)
	}
}

// runOnce is a single attempt. The rollback is deferred *inside* this function
// rather than in the retry loop, which is what makes retrying safe: the failed
// attempt is guaranteed to be rolled back before the next BeginTx.
func (p *Pool) runOnce(ctx context.Context, iso pgx.TxIsoLevel, lock string, fn func(Conn) error) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if lock != "" {
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lock); err != nil {
			return fmt.Errorf("acquire advisory lock %q: %w", lock, err)
		}
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// backoff waits before the next attempt, respecting context cancellation.
// Full jitter, because retrying contended transactions in lockstep just
// reproduces the contention.
func backoff(ctx context.Context, attempt int) error {
	const base = 2 * time.Millisecond
	// The shift is clamped before the ceiling comparison: base << attempt
	// overflows int64 around attempt 42, going negative before the ceiling
	// check could catch it, and a negative window panics rand.Int64N. Retries
	// is caller-controlled, so this is an input guard, not paranoia.
	window := base << min(attempt, 7)
	if window > 200*time.Millisecond {
		window = 200 * time.Millisecond
	}
	timer := time.NewTimer(time.Duration(rand.Int64N(int64(window)) + 1))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// IsRetryable reports whether err is a transient concurrency failure that the
// same transaction, retried unchanged, may well survive.
//
// Detection is by SQLSTATE, not by constraint name. That distinction matters:
// a serialization failure carries no constraint name at all, which is why the
// previous implementation's constraint-name error classifier could never have
// recognised one.
func IsRetryable(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "40001": // serialization_failure
		return true
	case "40P01": // deadlock_detected
		return true
	default:
		return false
	}
}
