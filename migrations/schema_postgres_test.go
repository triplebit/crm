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
	// Registered after seedUser so it runs before it: consents reference
	// users with no ON DELETE clause, so the user delete fails while any
	// consent survives — which is how this test used to leak a user and two
	// consents into the shared database on every run.
	t.Cleanup(func() {
		if _, err := pool.Conn().Exec(context.Background(),
			`DELETE FROM consents WHERE user_id = $1`, userID); err != nil {
			t.Errorf("consent cleanup failed: %v", err)
		}
	})

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
		if _, err := pool.Conn().Exec(context.Background(),
			`DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Errorf("seedUser cleanup failed, leaking a row: %v", err)
		}
	})
	return id
}

func seedCatalogItem(t *testing.T, ctx context.Context, pool *db.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "test-item-" + uuid.New().String()[:8]
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO catalog_items (id, slug, name, sku, kind, program)
		VALUES ($1, $2, 'Test item', $3, 'device', 'hotspot')
	`, id, slug, slug); err != nil {
		t.Fatalf("seed catalog item: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(), `DELETE FROM catalog_items WHERE id = $1`, id)
	})
	return id
}

// Migration 000003: ciphertext columns hold cryptox text envelopes, the shape
// is enforced, and rotation can select rows by the key id embedded in the
// envelope — with no key_id column to disagree with it.
func TestCiphertextColumnsEnforceEnvelopesAndSupportRotationSelection(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	// One pending membership order per user is itself a schema rule, so each
	// order here belongs to its own user.
	insert := func(id uuid.UUID, envelope string) error {
		userID := seedUser(t, ctx, pool)
		_, err := pool.Conn().Exec(ctx, `
			INSERT INTO orders (id, user_id, program, environment, account_ref,
			                    state, currency, imei_ciphertext, idempotency_key)
			VALUES ($1, $2, 'hotspot', 'sandbox', 'memberships',
			        'draft', 'usd', $3, $4)
		`, id, userID, envelope, id.String())
		return err
	}

	if err := insert(uuid.New(), "not an envelope"); err == nil {
		t.Fatal("a non-envelope ciphertext was accepted")
	}

	oldKey, newKey := uuid.New(), uuid.New()
	if err := insert(oldKey, "v1.pii-v1.AAAA"); err != nil {
		t.Fatalf("insert old-key envelope: %v", err)
	}
	if err := insert(newKey, "v1.pii-v2.BBBB"); err != nil {
		t.Fatalf("insert new-key envelope: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(),
			`DELETE FROM orders WHERE id IN ($1, $2)`, oldKey, newKey)
	})

	// The rotate-pii selection: rows sealed under anything but the active
	// key. Re-sealing removes a row from this predicate, which is what makes
	// the query its own resumable cursor.
	var stale int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM orders
		WHERE imei_ciphertext IS NOT NULL
		  AND split_part(imei_ciphertext, '.', 2) <> 'pii-v2'
		  AND id IN ($1, $2)
	`, oldKey, newKey).Scan(&stale); err != nil {
		t.Fatalf("rotation selection: %v", err)
	}
	if stale != 1 {
		t.Errorf("rotation selection found %d stale rows, want exactly the pii-v1 one", stale)
	}
}

// The other two append-only tables. Only audit_events had a deliberate test;
// order_lines and order_state_history were exercised solely by accident, by a
// broken teardown that asserted nothing about being refused. These are the
// frozen-order-lines invariant from the roadmap's cannot-be-cut list, so the
// enforcement deserves to be watched failing.
//
// TRUNCATE is deliberately not covered: row-level triggers do not fire on it,
// and the defence there is role separation — the migrate credential owns the
// tables, the serve and worker credentials do not, so the application cannot
// issue TRUNCATE at all. A trigger would duplicate a control that belongs to
// the grant.
func TestOrderLinesAndStateHistoryAreAppendOnly(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	userID := seedUser(t, ctx, pool)
	orderID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO orders (id, user_id, program, environment, account_ref, state,
		                    currency, idempotency_key)
		VALUES ($1, $2, 'hotspot', 'sandbox', 'memberships', 'checkout_pending', 'usd', $3)
	`, orderID, userID, orderID.String()); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	t.Cleanup(func() { testdb.PurgeOrders(t, pool, userID) })

	lineID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO order_lines (id, order_id, line_number, kind, slug, name,
		                         amount, currency, quantity, account_ref)
		VALUES ($1, $2, 1, 'hotspot_tier', 'test-slug', 'Test line',
		        7500, 'usd', 1, 'memberships')
	`, lineID, orderID); err != nil {
		t.Fatalf("seed line: %v", err)
	}
	historyID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO order_state_history (id, order_id, from_state, to_state, reason, source)
		VALUES ($1, $2, NULL, 'checkout_pending', 'test', 'member')
	`, historyID, orderID); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	for _, tc := range []struct {
		name, statement string
		arg             uuid.UUID
	}{
		{"order line update", `UPDATE order_lines SET amount = 1 WHERE id = $1`, lineID},
		{"order line delete", `DELETE FROM order_lines WHERE id = $1`, lineID},
		{"state history update", `UPDATE order_state_history SET reason = 'x' WHERE id = $1`, historyID},
		{"state history delete", `DELETE FROM order_state_history WHERE id = $1`, historyID},
	} {
		if _, err := pool.Conn().Exec(ctx, tc.statement, tc.arg); err == nil {
			t.Errorf("%s succeeded; what was sold and how it got there must be immutable", tc.name)
		}
	}

	// Both rows must survive, since none of those statements may have run.
	var lines, history int
	if err := pool.Conn().QueryRow(ctx, `
		SELECT (SELECT count(*) FROM order_lines WHERE id = $1),
		       (SELECT count(*) FROM order_state_history WHERE id = $2)
	`, lineID, historyID).Scan(&lines, &history); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if lines != 1 || history != 1 {
		t.Errorf("survivors: %d lines, %d history rows; want 1 and 1", lines, history)
	}
}

// Migration 000003's preflight refuses to convert ciphertext columns when any
// hold data, because the conversion is USING NULL and would erase them. The
// guard existing and the guard working are different claims: this runs the
// migration's own DO block, read out of the embedded migration itself, against
// a row that must trip it.
func TestMigration000003PreflightRefusesToDestroyCiphertext(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	var preflight string
	for _, m := range all {
		if !strings.Contains(m.Name, "pii_envelopes") {
			continue
		}
		start := strings.Index(m.SQL, "DO $$")
		end := strings.Index(m.SQL, "END $$;")
		if start < 0 || end < 0 {
			t.Fatal("migration 000003 no longer contains a DO-block preflight; this test is now lying")
		}
		preflight = m.SQL[start : end+len("END $$;")]
	}
	if preflight == "" {
		t.Fatal("migration 000003 was not found")
	}

	// Only refusal is asserted, not acceptance: sibling tests legitimately
	// hold ciphertext in this shared database at the same moment, so "the
	// guard passes on a clean database" is not a property one test can claim.
	userID := seedUser(t, ctx, pool)
	orderID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO orders (id, user_id, program, environment, account_ref, state,
		                    currency, imei_ciphertext, idempotency_key)
		VALUES ($1, $2, 'hotspot', 'sandbox', 'memberships', 'checkout_pending', 'usd',
		        'v1.pii-v1.AAAA', $3)
	`, orderID, userID, orderID.String()); err != nil {
		t.Fatalf("seed ciphertext: %v", err)
	}
	t.Cleanup(func() { testdb.PurgeOrders(t, pool, userID) })

	_, err = pool.Conn().Exec(ctx, preflight)
	if err == nil {
		t.Fatal("the preflight accepted a database holding ciphertext it would have erased")
	}
	if !strings.Contains(err.Error(), "unwritten") {
		t.Errorf("error %q does not explain the precondition", err)
	}
}

// Migration 000004's membership anchor. A membership is priced by exactly one
// of two things: a catalog price version, or — only for a custom-amount
// Friends subscription, where the member set the price — the immutable order
// line it was sold under. Every other combination must be impossible.
func TestMembershipMustHaveExactlyOnePriceAnchor(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	userID := seedUser(t, ctx, pool)
	itemID := seedCatalogItem(t, ctx, pool)
	t.Cleanup(func() { testdb.PurgeOrders(t, pool, userID) })

	// A verified version to anchor the catalog-priced cases.
	versionID := uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO catalog_price_versions (id, catalog_item_id, environment, account_ref,
		    stripe_product_id, stripe_price_id, amount, currency, recurring,
		    billing_interval, interval_count, active_from)
		VALUES ($1, $2, 'sandbox', 'donations', 'prod_anchor', 'price_anchor',
		        2500, 'usd', true, 'month', 1, now())
	`, versionID, itemID); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Conn().Exec(context.Background(),
			`DELETE FROM catalog_price_versions WHERE id = $1`, versionID)
	})

	// An order line to anchor the custom case.
	orderID, lineID := uuid.New(), uuid.New()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO orders (id, user_id, program, environment, account_ref, state,
		                    currency, idempotency_key)
		VALUES ($1, $2, 'friends', 'sandbox', 'donations', 'paid', 'usd', $3)
	`, orderID, userID, orderID.String()); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO order_lines (id, order_id, line_number, kind, slug, name,
		                         amount, currency, quantity, account_ref)
		VALUES ($1, $2, 1, 'friends_tier', 'friends-custom', 'Custom',
		        1250, 'usd', 1, 'donations')
	`, lineID, orderID); err != nil {
		t.Fatalf("seed line: %v", err)
	}

	insert := func(program string, version, line *uuid.UUID) error {
		id := uuid.New()
		account := "donations"
		if program == "hotspot" {
			account = "memberships"
		}
		_, err := pool.Conn().Exec(ctx, `
			INSERT INTO memberships (id, user_id, program, environment, account_ref,
			    tier_price_version_id, source_order_line_id, stripe_customer_id,
			    stripe_subscription_id, status)
			VALUES ($1, $2, $3, 'sandbox', $4, $5, $6, 'cus_x', $7, 'active')
		`, id, userID, program, account, version, line, id.String())
		if err == nil {
			// Memberships are not append-only, so a success can be cleaned up.
			_, _ = pool.Conn().Exec(ctx, `DELETE FROM memberships WHERE id = $1`, id)
		}
		return err
	}

	if err := insert("friends", &versionID, nil); err != nil {
		t.Errorf("a catalog-priced Friends membership was refused: %v", err)
	}
	if err := insert("friends", nil, &lineID); err != nil {
		t.Errorf("a custom-amount Friends membership anchored to its order line was refused: %v", err)
	}
	if err := insert("friends", nil, nil); err == nil {
		t.Error("a membership with no price anchor at all was accepted")
	}
	if err := insert("friends", &versionID, &lineID); err == nil {
		t.Error("a membership with both anchors was accepted; exactly one must apply")
	}
	// Hotspot has no custom-amount path, so it may never anchor on a line.
	if err := insert("hotspot", nil, &lineID); err == nil {
		t.Error("a hotspot membership anchored to an order line was accepted")
	}
}

// Migration 000004's lease shape. A claim must carry both a token and a
// deadline or neither, so a 'processing' row is always recoverable.
func TestWebhookLeaseIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)

	insert := func(state string, token *uuid.UUID, until *string) error {
		id := uuid.New()
		_, err := pool.Conn().Exec(ctx, `
			INSERT INTO webhook_events (id, environment, account_ref, stripe_event_id,
			    event_type, payload, processing_state, lease_token, leased_until)
			VALUES ($1, 'sandbox', 'memberships', $2, 'test.event', '{}'::jsonb,
			        $3, $4, $5::timestamptz)
		`, id, "evt_"+strings.ReplaceAll(id.String(), "-", ""), state, token, until)
		if err == nil {
			_, _ = pool.Conn().Exec(ctx, `DELETE FROM webhook_events WHERE id = $1`, id)
		}
		return err
	}

	token := uuid.New()
	future := "2030-01-01T00:00:00Z"

	if err := insert("pending", nil, nil); err != nil {
		t.Errorf("an unclaimed pending event was refused: %v", err)
	}
	if err := insert("processing", &token, &future); err != nil {
		t.Errorf("a properly claimed event was refused: %v", err)
	}
	if err := insert("processing", nil, nil); err == nil {
		t.Error("a 'processing' event with no lease was accepted; it would be unrecoverable")
	}
	if err := insert("processing", &token, nil); err == nil {
		t.Error("a claim with no deadline was accepted; it would never expire")
	}
	if err := insert("pending", &token, &future); err == nil {
		t.Error("a pending event holding a lease was accepted")
	}
}

// Migration 000004's non-empty guards. An empty idempotency key is not a key.
func TestIdempotencyKeysMayNotBeEmpty(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	userID := seedUser(t, ctx, pool)
	t.Cleanup(func() { testdb.PurgeOrders(t, pool, userID) })

	_, err := pool.Conn().Exec(ctx, `
		INSERT INTO orders (id, user_id, program, environment, account_ref, state,
		                    currency, idempotency_key)
		VALUES ($1, $2, 'hotspot', 'sandbox', 'memberships', 'draft', 'usd', '')
	`, uuid.New(), userID)
	if err == nil {
		t.Error("an order with an empty idempotency key was accepted")
	}
}
