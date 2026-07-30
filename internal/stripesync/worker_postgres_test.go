package stripesync_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripesync"
)

// These tests run the real loop rather than calling its pieces. What M6 claims
// is that a process settles orders on its own, and a test that invoked sweep()
// directly would prove the sweep works while leaving the thing that must call
// it — the timer in Run — untested.

// runWorker starts a worker with test-speed intervals and returns a wait
// function that stops it. sweeper may be nil, in which case a no-op stands in.
func runWorker(t *testing.T, f *settlementFixture, sweeper stripesync.Sweeper) (context.Context, func()) {
	t.Helper()
	if sweeper == nil {
		sweeper = noopSweeper{}
	}
	worker, err := stripesync.NewWorker(stripesync.WorkerOptions{
		Projector: f.projector, Inbox: inbox.New(), Billing: billing.New(),
		Pool: f.pool, Sweeper: sweeper, Environment: core.StripeSandbox,
		Logger:   slog.New(slog.DiscardHandler),
		IdlePoll: 5 * time.Millisecond, SweepEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	return ctx, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("worker returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the worker did not stop when its context was cancelled")
		}
	}
}

type noopSweeper struct{}

func (noopSweeper) SweepAbandoned(context.Context, int) (int, error) { return 0, nil }

// eventually polls until check passes, which is how a test observes a loop
// without sleeping for a fixed guess.
func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// M6's gate, as a test: money arrives, and the order settles with nobody
// looking at a page. Every other settlement test drives ProcessOne by hand;
// this one proves the process does it unprompted.
func TestWorkerSettlesAPaidOrderWithNobodyWatching(t *testing.T) {
	f := newSettlement(t, "hotspot")

	f.fake.SettleSession(f.sessionID, "pi_worker1", "sub_worker1")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)

	_, stop := runWorker(t, f, nil)
	defer stop()

	eventually(t, "the order to settle", func() bool { return f.orderState(t) == "paid" })
}

// An event past its attempt budget must become visible to a person. Until it
// does, the failure is silent in the worst possible way: the member paid, has
// nothing, and no page anywhere is wrong.
func TestWorkerEscalatesDeadLettersToStaffAlerts(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()

	event := f.receive(t, "checkout.session.completed", f.sessionID, core.Donations)
	// Force the row into the state a genuinely unprocessable event reaches
	// after its retries: reproducing that many real failures would test
	// Stripe's retry schedule, not this escalation.
	if _, err := f.pool.Conn().Exec(ctx, `
		UPDATE webhook_events
		SET processing_state = 'failed', attempts = max_attempts,
		    last_error = 'projection failed permanently',
		    lease_token = NULL, leased_until = NULL
		WHERE stripe_event_id = $1
	`, event.StripeID); err != nil {
		t.Fatalf("mark dead: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(ctx,
			`DELETE FROM staff_alerts WHERE source_key = $1`, "event:"+event.StripeID)
	})

	_, stop := runWorker(t, f, nil)
	defer stop()

	var count int
	var account, message string
	eventually(t, "a staff alert", func() bool {
		err := f.pool.Conn().QueryRow(ctx, `
			SELECT count(*), COALESCE(max(account_ref), ''), COALESCE(max(message), '')
			FROM staff_alerts WHERE source_key = $1
		`, "event:"+event.StripeID).Scan(&count, &account, &message)
		return err == nil && count > 0
	})

	// The account must be the event's own, not a default: an alert filed
	// against the wrong ledger sends whoever reads it to the wrong Stripe
	// account and wastes the one thing this alert exists to buy — attention.
	if account != core.Donations.String() {
		t.Errorf("alert account = %q, want %q", account, core.Donations.String())
	}
	if message == "" {
		t.Error("the alert carries no cause; a human cannot act on it")
	}

	// It must stay one alert however long the worker runs: RaiseAlert
	// deduplicates on the source key, and a queue that re-alerts every few
	// milliseconds is noise, not a control.
	time.Sleep(100 * time.Millisecond)
	var again int
	if err := f.pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM staff_alerts WHERE source_key = $1`,
		"event:"+event.StripeID).Scan(&again); err != nil {
		t.Fatalf("recount alerts: %v", err)
	}
	if again != 1 {
		t.Errorf("%d alerts for one dead letter; the sweep must deduplicate", again)
	}
}

// Stale checkouts nobody returns to must be retired by the worker.
//
// The member path abandons its own stale order, but only if somebody comes back
// to trigger it. Nobody does, so the worker has to — otherwise the order stays
// in checkout_pending forever, its Stripe session stays payable for its full
// 24 hours, and the one-pending-order index blocks that member from ever
// starting again.
func TestWorkerSweepRetiresStaleCheckouts(t *testing.T) {
	f := newSettlement(t, "hotspot")

	if got := f.orderState(t); got != "checkout_pending" {
		t.Fatalf("order starts as %s; this test would prove nothing", got)
	}

	// A sweeper whose clock is a day ahead: the order is past its resume
	// window without the test having to wait twenty hours for it.
	_, stop := runWorker(t, f, staleSweeper(t, f, 21*time.Hour))
	defer stop()

	eventually(t, "the stale order to be abandoned", func() bool {
		return f.orderState(t) == "expired"
	})

	// Unpayable, and at Stripe: an order retired locally whose session stays
	// open for another four hours is money arriving for an order the portal has
	// given up on, which is the case that pages a human.
	if f.fake.Session(f.sessionID, "status") != "expired" {
		t.Error("the order was retired while its Checkout Session was still payable")
	}
}

// The other half of that ordering, through the sweep: an order paid inside the
// abandonment window is left alone. Stripe refuses to expire a completed
// session, and that refusal is what stops the sweep — the money is already in,
// and the projector owns the order now.
func TestWorkerSweepLeavesAPaidStaleOrderAlone(t *testing.T) {
	f := newSettlement(t, "hotspot")

	f.fake.SettleSession(f.sessionID, "pi_sweep_paid", "sub_sweep_paid")

	_, stop := runWorker(t, f, staleSweeper(t, f, 21*time.Hour))
	defer stop()

	// Give the sweep several passes to do the wrong thing.
	time.Sleep(200 * time.Millisecond)

	if got := f.orderState(t); got != "checkout_pending" {
		t.Errorf("order state = %s; a paid order must not be swept away before it settles", got)
	}
}

// staleSweeper is the real Abandoner with its clock moved forward, which is how
// an order becomes stale in a test without waiting twenty hours for it.
//
// It also stands as the check that the worker can build its sweeper without the
// PII keyring: this constructor does not accept one.
func staleSweeper(t *testing.T, f *settlementFixture, ahead time.Duration) stripesync.Sweeper {
	t.Helper()
	sweeper, err := checkout.NewAbandoner(orders.New(), f.pool, f.pay, core.StripeSandbox,
		func() time.Time { return time.Now().UTC().Add(ahead) })
	if err != nil {
		t.Fatalf("NewAbandoner: %v", err)
	}
	return sweeper
}
