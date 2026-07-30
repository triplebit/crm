// Package testdb connects tests to a real PostgreSQL database.
//
// The strategy is carried over from the previous implementation, which got this
// part right: each test applies the migrations itself and namespaces its rows,
// so a single shared database serves the whole suite with no fixtures, no
// truncation between tests and no ordering constraints.
//
// What is *not* carried over is the silent skip. Previously a test needing a
// database called t.Skip when PORTAL_TEST_DATABASE_URL was unset, and CI never
// set it, so `make test` reported success while skipping every test that
// touched the database — which is how four integration tests stayed broken from
// the first commit to the last. Here, PORTAL_REQUIRE_DB_TESTS=1 turns that skip
// into a failure, and CI sets it. A database test that can silently skip in CI
// is not a test.
package testdb

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/migrations"
)

const (
	urlEnv     = "PORTAL_TEST_DATABASE_URL"
	requireEnv = "PORTAL_REQUIRE_DB_TESTS"
)

var (
	migrateOnce sync.Once
	migrateErr  error
)

// Pool returns a pool against the test database, applying the migrations once
// per process. It skips the test when no database is configured, unless
// PORTAL_REQUIRE_DB_TESTS=1, in which case it fails.
func Pool(t *testing.T) *db.Pool {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(urlEnv))
	if dsn == "" {
		if required() {
			t.Fatalf("%s is set but %s is empty: this test needs a database and must not be skipped in CI",
				requireEnv, urlEnv)
		}
		t.Skipf("set %s to run tests that need PostgreSQL (or %s=1 to make that mandatory)",
			urlEnv, requireEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", urlEnv, err)
	}
	t.Cleanup(pool.Close)

	migrateOnce.Do(func() {
		migrateErr = migrations.Migrate(ctx, pool.Pgx())
	})
	if migrateErr != nil {
		t.Fatalf("apply migrations to the test database: %v", migrateErr)
	}

	return pool
}

// required reports whether a missing database must fail rather than skip.
func required() bool {
	switch strings.TrimSpace(os.Getenv(requireEnv)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
