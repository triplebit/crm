// Package migrations embeds and applies the portal's PostgreSQL schema.
package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.sql
var files embed.FS

const advisoryLockKey int64 = 0x545249504c454249 // "TRIPLEBI"

// Migration is an immutable embedded schema change.
type Migration struct {
	Version  int64
	Name     string
	SQL      string
	Checksum string
}

type appliedMigration struct {
	Name     string
	Checksum string
}

// All returns embedded migrations in ascending version order.
func All() ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	seen := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".sql" {
			continue
		}
		versionText, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q must use VERSION_name.sql", entry.Name())
		}
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has invalid version", entry.Name())
		}
		if previous, duplicate := seen[version]; duplicate {
			return nil, fmt.Errorf("migration version %d is duplicated by %q and %q", version, previous, entry.Name())
		}
		body, err := files.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		sum := sha256.Sum256(body)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     entry.Name(),
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
		seen[version] = entry.Name()
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

// Migrate applies all pending migrations while holding a transaction-scoped
// advisory lock. An applied migration whose embedded checksum changed fails
// closed instead of silently mutating schema history.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("migration pool is nil")
	}
	all, err := All()
	if err != nil {
		return err
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migrations: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			name text NOT NULL,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	applied := make(map[int64]appliedMigration)
	rows, err := tx.Query(ctx, `
		SELECT version, name, checksum
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}
	for rows.Next() {
		var version int64
		var migration appliedMigration
		if err := rows.Scan(
			&version,
			&migration.Name,
			&migration.Checksum,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[version] = migration
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate applied migrations: %w", err)
	}
	rows.Close()

	if err := validateApplied(all, applied, true); err != nil {
		return err
	}
	for _, migration := range all {
		if _, exists := applied[migration.Version]; exists {
			continue
		}

		results, err := tx.Conn().PgConn().Exec(ctx, migration.SQL).ReadAll()
		if err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", migration.Version, migration.Name, err)
		}
		for _, result := range results {
			if result.Err != nil {
				return fmt.Errorf("apply migration %d (%s): %w", migration.Version, migration.Name, result.Err)
			}
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			migration.Version,
			migration.Name,
			migration.Checksum,
		); err != nil {
			return fmt.Errorf("record migration %d: %w", migration.Version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

// Verify fails unless the database migration ledger exactly matches this
// binary's embedded migrations. It is intended for readiness checks after the
// explicit migration command has run.
func Verify(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("migration pool is nil")
	}
	all, err := All()
	if err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `
		SELECT version, name, checksum
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]appliedMigration)
	for rows.Next() {
		var version int64
		var migration appliedMigration
		if err := rows.Scan(
			&version,
			&migration.Name,
			&migration.Checksum,
		); err != nil {
			return fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = migration
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration ledger: %w", err)
	}
	return validateApplied(all, applied, false)
}

func validateApplied(
	embedded []Migration,
	applied map[int64]appliedMigration,
	allowPending bool,
) error {
	known := make(map[int64]Migration, len(embedded))
	for _, migration := range embedded {
		known[migration.Version] = migration
		record, exists := applied[migration.Version]
		if !exists {
			if allowPending {
				continue
			}
			return fmt.Errorf(
				"migration %d (%s) is pending",
				migration.Version,
				migration.Name,
			)
		}
		if record.Name != migration.Name {
			return fmt.Errorf(
				"migration %d name changed: database=%q embedded=%q",
				migration.Version,
				record.Name,
				migration.Name,
			)
		}
		if record.Checksum != migration.Checksum {
			return fmt.Errorf(
				"migration %d checksum changed: database=%s embedded=%s",
				migration.Version,
				record.Checksum,
				migration.Checksum,
			)
		}
	}
	for version, record := range applied {
		if _, exists := known[version]; !exists {
			return fmt.Errorf(
				"database contains unknown migration %d (%s)",
				version,
				record.Name,
			)
		}
	}
	return nil
}
