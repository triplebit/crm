package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/testdb"
	"triplebit.org/portal/migrations"
)

// The schema is the most valuable artifact carried forward from the previous
// implementation, because it puts the business rules in the database rather than
// in Go, where every code path has to remember them. These tests assert the
// rules by trying to break them against a real PostgreSQL, rather than by
// grepping the SQL text for substrings: a substring proves the file says
// something, an INSERT that is refused proves the database enforces it.

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t) // already migrated once

	if err := migrations.Migrate(ctx, pool.Pgx()); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}
	if err := migrations.Verify(ctx, pool.Pgx()); err != nil {
		t.Fatalf("Verify failed after migrating: %v", err)
	}

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	var ledger int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations`).Scan(&ledger); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if ledger != len(all) {
		t.Errorf("ledger has %d rows, embedded migrations = %d", ledger, len(all))
	}
}

// expectedTables is every table the migrations create. Naming them, rather
// than counting them, means a failure says which table is missing or
// unexpected instead of only that a number changed. 40 come from 000001;
// login_transactions from 000002.
var expectedTables = []string{
	"acknowledgment_deliveries", "acknowledgments", "assets", "audit_events",
	"browser_sessions", "catalog_items", "catalog_price_versions", "consents",
	"disputes", "donations", "donor_notes", "donor_tags", "effective_groups",
	"entitlement_projections", "financial_invalidations", "fulfillments",
	"guest_donor_tags", "guest_donors", "hotspot_device_replacement_requirements",
	"inventory", "inventory_reservations", "invoices", "login_transactions",
	"memberships", "order_lines",
	"order_state_history", "orders", "outbox_jobs", "payment_attempts", "refunds",
	"staff_alerts", "staff_roles", "stripe_bank_setup_attempts",
	"stripe_customer_creation_intents", "stripe_customers",
	"stripe_projection_applications", "stripe_reconciliation_checkpoints",
	"stripe_reconciliation_object_failures", "user_donor_tags", "users",
	"webhook_events",
}

func TestSchemaCreatesEveryExpectedTable(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	rows, err := pool.Conn().Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		  AND table_name <> 'schema_migrations'
		ORDER BY table_name
	`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()

	found := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}

	want := make(map[string]bool, len(expectedTables))
	for _, name := range expectedTables {
		want[name] = true
		if !found[name] {
			t.Errorf("table %q is missing from the schema", name)
		}
	}
	for name := range found {
		if !want[name] {
			t.Errorf("unexpected table %q in the public schema", name)
		}
	}

	if len(expectedTables) != 41 {
		t.Errorf("expectedTables lists %d tables, want 41", len(expectedTables))
	}
}

// Verify must fail closed when the ledger no longer matches the binary. This is
// the integration counterpart to the unit tests on validateApplied: it proves
// Verify really does read this table, and really does refuse.
//
// The phantom row is committed, because Verify reads through the pool and would
// not see an uncommitted one. Cleanup removes it, and the version is chosen far
// outside any plausible real range so a leaked row is obvious.
func TestVerifyFailsWhenTheLedgerIsTampered(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	if err := migrations.Verify(ctx, pool.Pgx()); err != nil {
		t.Fatalf("Verify failed before tampering: %v", err)
	}

	const phantom = 999999
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(),
			`DELETE FROM schema_migrations WHERE version = $1`, phantom)
	})
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO schema_migrations (version, name, checksum)
		VALUES ($1, '999999_from_the_future.sql', 'deadbeef')
	`, phantom); err != nil {
		t.Fatalf("insert phantom migration: %v", err)
	}

	err := migrations.Verify(ctx, pool.Pgx())
	if err == nil {
		t.Fatal("Verify accepted a ledger containing a migration this binary does not know about")
	}
	if !strings.Contains(err.Error(), "unknown migration") {
		t.Errorf("error %q does not explain that the database is ahead of the binary", err)
	}
}

func TestReservedStockCanNeverExceedStockOnHand(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	itemID := seedCatalogItem(t, ctx, pool)

	invID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO inventory (id, catalog_item_id, variant, on_hand, reserved, safety_stock)
		VALUES ($1, $2, 'default', 5, 0, 0)
	`, invID, itemID); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM inventory WHERE id = $1`, invID)
	})

	_, err := pool.Conn().Exec(ctx,
		`UPDATE inventory SET reserved = 6 WHERE id = $1`, invID)
	if err == nil {
		t.Fatal("reserved was allowed to exceed on_hand; overselling devices must be impossible in the database")
	}
	if got := db.Normalize(err); !errors.Is(got, db.ErrInvalid) {
		t.Errorf("error classified as %v, want db.ErrInvalid", got)
	}
}

func TestAppendOnlyTablesRejectUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	id := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO audit_events (id, actor_kind, action, target_type, target_id, occurred_at)
		VALUES ($1, 'system', 'test.append_only', 'test', $2, now())
	`, id, id.String()); err != nil {
		t.Fatalf("insert audit event: %v", err)
	}

	if _, err := pool.Conn().Exec(ctx,
		`UPDATE audit_events SET action = 'tampered' WHERE id = $1`, id); err == nil {
		t.Error("an audit event was updated; the audit trail must be append-only")
	}
	if _, err := pool.Conn().Exec(ctx,
		`DELETE FROM audit_events WHERE id = $1`, id); err == nil {
		t.Error("an audit event was deleted; the audit trail must be append-only")
	}

	// The row must still be there, since neither statement may have succeeded.
	var count int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE id = $1`, id).Scan(&count); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if count != 1 {
		t.Errorf("audit event count = %d, want 1", count)
	}
}

// Consent is an authorization, so only one grant per (subject, kind, version)
// may be live at a time — but withdrawing and re-granting must be possible, and
// the history must survive. This is the schema half of the fix for a gate that
// previously accepted any prior row even when the box was left unticked.
func TestOnlyOneLiveConsentPerVersionButHistoryIsKept(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	userID := seedUser(t, ctx, pool)

	insert := func(id uuid.UUID) error {
		_, err := pool.Conn().Exec(ctx, `
			INSERT INTO consents (id, user_id, kind, version, content_sha256, accepted_at)
			VALUES ($1, $2, 'stripe_sharing', 'v1',
			        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', now())
		`, id, userID)
		return err
	}

	first := uuid.New()
	if err := insert(first); err != nil {
		t.Fatalf("record first consent: %v", err)
	}

	// A second live grant at the same version must be refused.
	if err := insert(uuid.New()); err == nil {
		t.Fatal("two live consents were allowed for the same version")
	} else if got := db.Normalize(err); !errors.Is(got, db.ErrConflict) {
		t.Errorf("error classified as %v, want db.ErrConflict", got)
	}

	// Withdraw, then re-grant: allowed, and the withdrawn row is retained.
	if _, err := pool.Conn().Exec(ctx,
		`UPDATE consents SET withdrawn_at = now() WHERE id = $1`, first); err != nil {
		t.Fatalf("withdraw consent: %v", err)
	}
	second := uuid.New()
	if err := insert(second); err != nil {
		t.Fatalf("re-grant after withdrawal was refused: %v", err)
	}

	var total, live int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE withdrawn_at IS NULL)
		FROM consents WHERE user_id = $1
	`, userID).Scan(&total, &live); err != nil {
		t.Fatalf("count consents: %v", err)
	}
	if total != 2 {
		t.Errorf("consent history has %d rows, want 2: withdrawal must not erase what was agreed", total)
	}
	if live != 1 {
		t.Errorf("%d live consents, want 1", live)
	}
}

// A session row is meaningless without the person it belongs to, and erasing a
// person must not leave their sessions behind.
func TestDeletingAUserCascadesToTheirSessions(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	userID := seedUser(t, ctx, pool)

	tokenHash := make([]byte, 32)
	tokenHash[0] = 7
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO browser_sessions (
			token_hash, user_id, csrf_ciphertext, login_method,
			authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		) VALUES ($1, $2, 'envelope', 'passkey',
		          now(), now(), now(), now() + interval '30 minutes', now() + interval '12 hours')
	`, tokenHash, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	if _, err := pool.Conn().Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	var remaining int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM browser_sessions WHERE user_id = $1`, userID).Scan(&remaining); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if remaining != 0 {
		t.Errorf("%d sessions survived the user being deleted", remaining)
	}
}

func TestSessionTokenHashMustBeExactlyThirtyTwoBytes(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	userID := seedUser(t, ctx, pool)
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	_, err := pool.Conn().Exec(ctx, `
		INSERT INTO browser_sessions (
			token_hash, user_id, csrf_ciphertext, login_method,
			authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		) VALUES ($1, $2, 'envelope', 'passkey',
		          now(), now(), now(), now() + interval '30 minutes', now() + interval '12 hours')
	`, []byte("too short"), userID)
	if err == nil {
		t.Fatal("a token hash that is not a 32-byte digest was accepted")
	}
}

// Helpers. Each seeds the minimum row needed and registers its own cleanup, so
// tests stay independent and a single shared database serves the whole suite.

func seedUser(t *testing.T, ctx context.Context, pool *db.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO users (id, pocket_id_sub, email, email_verified)
		VALUES ($1, $2, $3, true)
	`, id, "sub-"+id.String(), id.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func seedCatalogItem(t *testing.T, ctx context.Context, pool *db.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "test-item-" + uuid.New().String()[:8]
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO catalog_items (id, slug, name, sku, kind, program, inventory_tracked)
		VALUES ($1, $2, 'Test item', $3, 'device', 'hotspot', true)
	`, id, slug, slug); err != nil {
		t.Fatalf("seed catalog item: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM catalog_items WHERE id = $1`, id)
	})
	return id
}
