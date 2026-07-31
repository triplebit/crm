package stripesync_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/repo/inbox"
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
// Deterministic, where it used to be iterated: the projector's test hook holds
// worker A between its canonical read and its transaction while worker B
// projects its own delivery of the same session to completion — the exact
// interleaving the old six-round loop could only hope to hit.
func TestTwoWorkersProjectingOneSessionNeitherDoubleSettleNorFalselyAlert(t *testing.T) {
	ctx := context.Background()

	f := newSettlement(t, "hotspot")
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	f.fake.SettleSession(f.sessionID, "pi_"+suffix, "sub_"+suffix)
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM staff_alerts WHERE source_key = $1`, "order:"+f.orderID.String())
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM stripe_projection_applications WHERE object_id = $1`, "sub_"+suffix)
	})

	// Two separate inbox rows naming the same session, so the claim hands one
	// to each worker instead of one worker taking both.
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)

	// Worker A claims first and pauses holding its canonical read.
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.projector.SetPauseBeforeTxForTest(func(e inbox.Event) {
		if e.Type != "checkout.session.completed" {
			return
		}
		once.Do(func() {
			close(paused)
			<-resume
		})
	})
	workerA := make(chan error, 1)
	go func() {
		_, err := f.projector.ProcessOne(ctx, time.Minute)
		workerA <- err
	}()
	<-paused

	// Worker B takes the second row — SKIP LOCKED walks past A's lease — and
	// settles the order to completion.
	workerB := projectorWith(t, f, nil)
	drainWith(t, workerB, 4)
	if got := f.orderState(t); got != "paid" {
		t.Fatalf("order state = %s; worker B should have settled while A was paused", got)
	}

	// A resumes holding an observation B has since superseded. It must record
	// the refusal and walk away — not alert, not double-settle, not fail.
	close(resume)
	if err := <-workerA; err != nil {
		t.Fatalf("worker A must absorb a duplicate delivery quietly, not fail: %v", err)
	}

	// The order settled, exactly once.
	var paidTransitions int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM order_state_history
		WHERE order_id = $1 AND to_state = 'paid'
	`, f.orderID).Scan(&paidTransitions); err != nil {
		t.Fatalf("count transitions: %v", err)
	}
	if paidTransitions != 1 {
		t.Errorf("%d paid transitions, want exactly 1", paidTransitions)
	}

	// And nobody was woken up. This is the assertion that fails without the
	// same-object transactional guard: a duplicate delivery is not an incident.
	var alerts int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM staff_alerts WHERE source_key = $1
	`, "order:"+f.orderID.String()).Scan(&alerts); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alerts != 0 {
		t.Errorf("%d staff alerts for a concurrent duplicate delivery; signals=%v",
			alerts, f.signalsFor(t, f.sessionID))
	}

	// Both events left an application record, including the one that lost.
	// An event with no record is invisible to the ordering guard, so a later
	// delivery could reach the same conclusion again.
	var applications int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM stripe_projection_applications WHERE object_id = $1
	`, f.sessionID).Scan(&applications); err != nil {
		t.Fatalf("count applications: %v", err)
	}
	if applications != 2 {
		t.Errorf("%d application records for 2 events; every projection must leave one", applications)
	}
	if signals := f.signalsFor(t, f.sessionID); !contains(signals, "superseded by a newer observation") {
		t.Errorf("signals %v do not record the loser's refusal", signals)
	}

	// Exactly one membership, however many events raced.
	var memberships int
	if err := f.pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE user_id = $1`, f.person.UserID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberships != 1 {
		t.Errorf("%d memberships, want 1", memberships)
	}
}
