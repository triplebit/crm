package db_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/testdb"
)

// scratchSchema holds the throwaway tables these tests create.
//
// They must not live in `public`. `go test ./...` runs package binaries
// concurrently against one shared database, so a scratch table in `public` is
// visible to the migrations package's schema assertions while it exists, and
// made them fail intermittently with "schema has 41 tables, want 40" — a flake
// that passed in isolation every time and, because cleanup is best effort,
// could survive a crashed run and become permanent.
//
// A dedicated schema fixes it at the source and needs no cooperation from the
// other package. Temporary tables would not work here: the write-skew tests
// need two sessions to see the same table, and a temp table is per-session.
const scratchSchema = "db_test_scratch"

// setupCounters creates a two-row table for provoking serialization failures.
// Each test gets its own table, so tests stay independent in a shared database.
func setupCounters(t *testing.T, ctx context.Context, pool *db.Pool) string {
	t.Helper()
	if _, err := pool.Conn().Exec(ctx,
		`CREATE SCHEMA IF NOT EXISTS `+scratchSchema); err != nil {
		t.Fatalf("create scratch schema: %v", err)
	}
	table := scratchSchema + ".tx_test_" + uuid.New().String()[:8]
	if _, err := pool.Conn().Exec(ctx,
		`CREATE TABLE `+table+` (id int PRIMARY KEY, n int NOT NULL)`); err != nil {
		t.Fatalf("create %s: %v", table, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DROP TABLE IF EXISTS `+table)
	})
	if _, err := pool.Conn().Exec(ctx,
		`INSERT INTO `+table+` (id, n) VALUES (1, 0), (2, 0)`); err != nil {
		t.Fatalf("seed %s: %v", table, err)
	}
	return table
}

// runCrossingPair runs two Serializable transactions that each read one row and
// write the other. Under Serializable isolation this pattern — write skew — is
// exactly what PostgreSQL must refuse, so one of the two reliably fails with
// SQLSTATE 40001. A barrier makes both read before either writes, so the
// conflict is deterministic rather than a race that usually happens.
func runCrossingPair(t *testing.T, pool *db.Pool, opts db.TxOptions) []error {
	t.Helper()
	table := setupCounters(t, context.Background(), pool)

	var bothRead sync.WaitGroup
	bothRead.Add(2)

	errs := make([]error, 2)
	var done sync.WaitGroup
	done.Add(2)

	for i := 0; i < 2; i++ {
		go func(i int) {
			defer done.Done()
			readID, writeID := 1, 2
			if i == 1 {
				readID, writeID = 2, 1
			}
			// Only the first attempt participates in the barrier; a retry must
			// not block waiting for a peer that has already finished.
			first := true
			errs[i] = pool.WithTx(context.Background(), opts, func(c db.Conn) error {
				var n int
				if err := c.QueryRow(context.Background(),
					`SELECT n FROM `+table+` WHERE id = $1`, readID).Scan(&n); err != nil {
					return err
				}
				if first {
					first = false
					bothRead.Done()
					bothRead.Wait()
				}
				_, err := c.Exec(context.Background(),
					`UPDATE `+table+` SET n = $1 WHERE id = $2`, n+1, writeID)
				return err
			})
		}(i)
	}

	done.Wait()
	return errs
}

// The gate for this milestone. Without retries, a legitimate concurrent write
// surfaces as an error the caller has to handle — which in the previous
// implementation meant a 500 for one of two people enrolling at the same
// moment, because it opened exactly one Serializable transaction and never
// wrote a retry loop anywhere.
func TestSerializationFailureIsSurfacedWithoutRetries(t *testing.T) {
	pool := testdb.Pool(t)

	errs := runCrossingPair(t, pool, db.TxOptions{Serializable: true, Retries: 0})

	var failures int
	for _, err := range errs {
		if err != nil {
			failures++
			if !db.IsRetryable(err) {
				t.Errorf("error is not classified as retryable: %v", err)
			}
		}
	}
	if failures != 1 {
		t.Fatalf("%d of 2 transactions failed, want exactly 1: the test did not provoke a serialization failure", failures)
	}
}

// The same conflict, with a retry budget, must resolve invisibly.
//
// The budget here is deliberately generous. Retries with millisecond jitter
// windows can re-cross the still-running peer transaction, and each unlucky
// crossing burns one retry; with Retries=3 that lost a CI run on a loaded
// two-core runner (2026-07-30, run 30518457344) while 600 local iterations
// never reproduced it. The property under test is "a retry budget makes the
// conflict invisible", not "three is always enough", so the test asserts the
// former with room for scheduler malice.
func TestSerializationFailureIsRetriedTransparently(t *testing.T) {
	pool := testdb.Pool(t)

	errs := runCrossingPair(t, pool, db.TxOptions{Serializable: true, Retries: 10})

	for i, err := range errs {
		if err != nil {
			t.Errorf("transaction %d failed despite Retries=3: %v", i, err)
		}
	}
}

func TestWithTxRollsBackWhenTheCallbackFails(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	table := setupCounters(t, ctx, pool)

	sentinel := errors.New("callback refused")
	err := pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		if _, err := c.Exec(ctx, `UPDATE `+table+` SET n = 99 WHERE id = 1`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx returned %v, want the callback's error", err)
	}

	var n int
	if err := pool.Conn().QueryRow(ctx, `SELECT n FROM `+table+` WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0: the failed transaction was not rolled back", n)
	}
}

func TestWithTxCommitsWhenTheCallbackSucceeds(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	table := setupCounters(t, ctx, pool)

	if err := pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		_, err := c.Exec(ctx, `UPDATE `+table+` SET n = 42 WHERE id = 1`)
		return err
	}); err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	var n int
	if err := pool.Conn().QueryRow(ctx, `SELECT n FROM `+table+` WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != 42 {
		t.Errorf("n = %d, want 42", n)
	}
}

// A non-retryable error must not be retried: repeating a transaction that
// violated a constraint just violates it again, more slowly.
func TestNonRetryableErrorIsNotRetried(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	table := setupCounters(t, ctx, pool)

	var attempts int
	err := pool.WithTx(ctx, db.TxOptions{Retries: 5}, func(c db.Conn) error {
		attempts++
		_, err := c.Exec(ctx, `INSERT INTO `+table+` (id, n) VALUES (1, 0)`) // duplicate key
		return err
	})
	if err == nil {
		t.Fatal("a duplicate key insert succeeded")
	}
	if attempts != 1 {
		t.Errorf("callback ran %d times, want 1: a constraint violation must not be retried", attempts)
	}
	if !errors.Is(err, db.ErrConflict) {
		t.Errorf("error %v is not classified as db.ErrConflict", err)
	}
	if got := db.ConstraintOf(err); got == "" {
		t.Error("ConstraintOf returned no constraint name for a unique violation")
	}
}

// The advisory lock is what serializes per-actor Stripe Customer creation, so
// two concurrent requests cannot produce two Customers for one person.
func TestAdvisoryLockSerializesTransactionsSharingAKey(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	table := setupCounters(t, ctx, pool)

	key := "test-actor-" + uuid.New().String()
	const workers = 8

	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			// Read-modify-write with no isolation protection at all. Without the
			// lock this loses updates; with it, every increment survives.
			errs[i] = pool.WithTx(ctx, db.TxOptions{Lock: key}, func(c db.Conn) error {
				var n int
				if err := c.QueryRow(ctx, `SELECT n FROM `+table+` WHERE id = 1`).Scan(&n); err != nil {
					return err
				}
				_, err := c.Exec(ctx, `UPDATE `+table+` SET n = $1 WHERE id = 1`, n+1)
				return err
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
	}

	var n int
	if err := pool.Conn().QueryRow(ctx, `SELECT n FROM `+table+` WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != workers {
		t.Errorf("n = %d, want %d: the advisory lock did not serialize the transactions", n, workers)
	}
}
