package stripesync_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
)

// Two workers projecting the same Stripe object at once must not contradict each
// other, and must not page a human for doing so.
//
// The race this covers: the freshness check and the order read used to run on the
// pool, before the write transaction opened, and the transaction then acted on
// those stale values. If another worker settled the order in between, `Settle`
// returned false while the stale copy still said `checkout_pending`, so the code
// fell into the "paid while not payable" branch — raising a critical alert for an
// ordinary duplicate delivery, and returning before `RecordApplication` so the
// event left no trace for the ordering guard.
//
// Two deliveries about one session is not something Stripe does with one event
// id; it is what happens when a lease is reaped while its original worker is
// merely slow rather than dead, and both then project the same object. The lease
// token protects the *finish*, never the projection.
//
// Iterated rather than orchestrated: there is no hook to pause a worker between
// its canonical read and its transaction, so this leans on repetition to hit the
// interleaving. Verified against the pre-fix code, where it fails.
func TestTwoWorkersProjectingOneSessionNeitherDoubleSettleNorFalselyAlert(t *testing.T) {
	ctx := context.Background()

	for round := range 6 {
		f := newSettlement(t, "hotspot")
		// Unique per round: each round is a new order, and the schema rightly
		// refuses to let one payment intent or subscription belong to two of them.
		suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		f.fake.SettleSession(f.sessionID, "pi_"+suffix, "sub_"+suffix)
		t.Cleanup(func() {
			_, _ = f.pool.Conn().Exec(context.Background(),
				`DELETE FROM staff_alerts WHERE source_key = $1`, "order:"+f.orderID.String())
		})

		// Two separate inbox rows naming the same session, so the claim hands one
		// to each worker instead of one worker taking both.
		f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
		f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// Each worker drains what it can; the claim is SKIP LOCKED so they
				// take different rows.
				for range 4 {
					worked, err := f.projector.ProcessOne(ctx, time.Minute)
					if err != nil {
						errs[i] = err
						return
					}
					if !worked {
						return
					}
				}
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d worker %d: %v", round, i, err)
			}
		}

		// The order settled, exactly once.
		if got := f.orderState(t); got != "paid" {
			t.Fatalf("round %d: order state = %s, want paid", round, got)
		}
		var paidTransitions int
		if err := f.pool.Conn().QueryRow(ctx, `
			SELECT count(*) FROM order_state_history
			WHERE order_id = $1 AND to_state = 'paid'
		`, f.orderID).Scan(&paidTransitions); err != nil {
			t.Fatalf("count transitions: %v", err)
		}
		if paidTransitions != 1 {
			t.Errorf("round %d: %d paid transitions, want exactly 1", round, paidTransitions)
		}

		// And nobody was woken up. This is the assertion that fails without the
		// fix: a duplicate delivery is not an incident.
		var alerts int
		if err := f.pool.Conn().QueryRow(ctx, `
			SELECT count(*) FROM staff_alerts WHERE source_key = $1
		`, "order:"+f.orderID.String()).Scan(&alerts); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		if alerts != 0 {
			t.Errorf("round %d: %d staff alerts for a concurrent duplicate delivery; signals=%v",
				round, alerts, f.signalsFor(t, f.sessionID))
		}

		// Both events left an application record, including whichever one lost.
		// An event with no record is invisible to the ordering guard, so a later
		// delivery could reach the same conclusion again.
		var applications int
		if err := f.pool.Conn().QueryRow(ctx, `
			SELECT count(*) FROM stripe_projection_applications WHERE object_id = $1
		`, f.sessionID).Scan(&applications); err != nil {
			t.Fatalf("count applications: %v", err)
		}
		if applications != 2 {
			t.Errorf("round %d: %d application records for 2 events; every projection must leave one",
				round, applications)
		}

		// Exactly one membership, however many events raced.
		var memberships int
		if err := f.pool.Conn().QueryRow(ctx,
			`SELECT count(*) FROM memberships WHERE user_id = $1`, f.person.UserID).Scan(&memberships); err != nil {
			t.Fatalf("count memberships: %v", err)
		}
		if memberships != 1 {
			t.Errorf("round %d: %d memberships, want 1", round, memberships)
		}
	}
}
