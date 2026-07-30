package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreOrderedAndChecksummed(t *testing.T) {
	t.Parallel()

	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no embedded migrations")
	}

	var previous int64
	for _, m := range all {
		if m.Version <= previous {
			t.Errorf("migration %q version %d is not strictly after %d", m.Name, m.Version, previous)
		}
		previous = m.Version

		if !strings.HasSuffix(m.Name, ".sql") {
			t.Errorf("migration %q is not a .sql file", m.Name)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("migration %q is empty", m.Name)
		}
		if len(m.Checksum) != 64 {
			t.Errorf("migration %q checksum %q is not a SHA-256 hex digest", m.Name, m.Checksum)
		}
	}
}

// The checksum must be a pure function of the file, so that re-reading the same
// embedded bytes always produces the ledger value recorded at apply time.
func TestChecksumIsStableAcrossCalls(t *testing.T) {
	t.Parallel()

	first, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	second, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("All() returned %d then %d migrations", len(first), len(second))
	}
	for i := range first {
		if first[i].Checksum != second[i].Checksum {
			t.Errorf("migration %q checksum is not stable: %s then %s",
				first[i].Name, first[i].Checksum, second[i].Checksum)
		}
	}
}

func TestValidateAppliedAcceptsAnExactLedger(t *testing.T) {
	t.Parallel()

	embedded := []Migration{{Version: 1, Name: "000001_initial.sql", Checksum: "abc"}}
	applied := map[int64]appliedMigration{1: {Name: "000001_initial.sql", Checksum: "abc"}}

	if err := validateApplied(embedded, applied, false); err != nil {
		t.Errorf("an exactly matching ledger was rejected: %v", err)
	}
}

// The property that matters most: an applied migration whose file changed must
// fail closed. Editing already-applied SQL means the database and the binary
// disagree about the schema, and continuing would build on a false assumption.
func TestValidateAppliedRejectsChecksumDrift(t *testing.T) {
	t.Parallel()

	embedded := []Migration{{Version: 1, Name: "000001_initial.sql", Checksum: "edited"}}
	applied := map[int64]appliedMigration{1: {Name: "000001_initial.sql", Checksum: "original"}}

	err := validateApplied(embedded, applied, true)
	if err == nil {
		t.Fatal("a changed checksum was accepted; applied migrations must be immutable")
	}
	if !strings.Contains(err.Error(), "checksum changed") {
		t.Errorf("error %q does not explain that the checksum changed", err)
	}
}

func TestValidateAppliedRejectsRenamedMigration(t *testing.T) {
	t.Parallel()

	embedded := []Migration{{Version: 1, Name: "000001_renamed.sql", Checksum: "abc"}}
	applied := map[int64]appliedMigration{1: {Name: "000001_initial.sql", Checksum: "abc"}}

	if err := validateApplied(embedded, applied, true); err == nil {
		t.Error("a renamed migration was accepted")
	}
}

// A database holding a migration this binary does not know about means an older
// binary is running against a newer schema. Refusing protects against a rollback
// quietly operating on tables it cannot reason about.
func TestValidateAppliedRejectsUnknownAppliedVersion(t *testing.T) {
	t.Parallel()

	embedded := []Migration{{Version: 1, Name: "000001_initial.sql", Checksum: "abc"}}
	applied := map[int64]appliedMigration{
		1: {Name: "000001_initial.sql", Checksum: "abc"},
		2: {Name: "000002_from_the_future.sql", Checksum: "def"},
	}

	err := validateApplied(embedded, applied, true)
	if err == nil {
		t.Fatal("an unknown applied migration was accepted")
	}
	if !strings.Contains(err.Error(), "unknown migration") {
		t.Errorf("error %q does not explain that the database is ahead", err)
	}
}

// Verify (allowPending=false) must refuse a database that is behind the binary;
// Migrate (allowPending=true) must accept it, because applying it is the job.
func TestPendingMigrationIsAnErrorOnlyForVerify(t *testing.T) {
	t.Parallel()

	embedded := []Migration{
		{Version: 1, Name: "000001_initial.sql", Checksum: "abc"},
		{Version: 2, Name: "000002_next.sql", Checksum: "def"},
	}
	applied := map[int64]appliedMigration{1: {Name: "000001_initial.sql", Checksum: "abc"}}

	if err := validateApplied(embedded, applied, true); err != nil {
		t.Errorf("Migrate rejected a pending migration: %v", err)
	}

	err := validateApplied(embedded, applied, false)
	if err == nil {
		t.Fatal("Verify accepted a pending migration; readiness must fail until the schema is current")
	}
	if !strings.Contains(err.Error(), "pending") {
		t.Errorf("error %q does not say the migration is pending", err)
	}
}
