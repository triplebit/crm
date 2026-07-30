package testdb

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/db"
)

// PurgeOrders removes every order belonging to one user, children included.
//
// It exists because the obvious teardown does not work and silently said it
// did. `order_lines` and `order_state_history` carry BEFORE UPDATE OR DELETE
// triggers that make them append-only — correctly, they are financial records
// — and `orders` sits behind an ON DELETE RESTRICT foreign key from those
// children. So a plain DELETE fails on every one of the three tables, and a
// teardown that discards the error leaks its rows into the shared test
// database on every run, forever. (Measured before this helper existed: seven
// orders, ten lines, eight history rows and seven users per suite run.)
//
// The honest fix is to say what the teardown means. `session_replication_role`
// suspends triggers for THIS SESSION ONLY — never globally, so a concurrent
// test asserting that the triggers work still sees them work — and `SET LOCAL`
// scopes it to this transaction, so it cannot outlive the teardown even if
// the transaction fails. Tests are allowed to delete what production may not;
// they are not allowed to pretend.
//
// Errors are fatal, not discarded. A teardown that cannot clean up must say so
// rather than accumulate.
func PurgeOrders(t *testing.T, pool *db.Pool, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	err := pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		if _, err := c.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		for _, statement := range []string{
			`DELETE FROM inventory_reservations WHERE order_line_id IN (
				SELECT l.id FROM order_lines l JOIN orders o ON o.id = l.order_id WHERE o.user_id = $1)`,
			`DELETE FROM order_state_history WHERE order_id IN (SELECT id FROM orders WHERE user_id = $1)`,
			`DELETE FROM order_lines WHERE order_id IN (SELECT id FROM orders WHERE user_id = $1)`,
			`DELETE FROM orders WHERE user_id = $1`,
		} {
			if _, err := c.Exec(ctx, statement, userID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("testdb: purge orders for %s: %v", userID, err)
	}
}
