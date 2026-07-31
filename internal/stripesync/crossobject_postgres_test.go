package stripesync_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripesync"
)

// The cross-object ordering races. Settlement resolves through the Checkout
// Session; the lifecycle resolves through the Subscription; both write the same
// membership. Locking and freshness-checking each path only on its OWN object
// meant the two never serialized with each other, so an older canonical
// Subscription read could overwrite a newer one — in either direction — and the
// overwritten event was already recorded, so no redelivery would ever repair it.
//
// These tests are deterministic, not iterated: the projector's test hook holds a
// projection at the exact point where its observation can be overtaken — after
// the canonical Stripe reads, before the transaction.

// projectorWith builds an extra projector over the fixture's stores, optionally
// with its own clock. The future clock is how a test drives a retry without
// waiting out the inbox backoff.
func projectorWith(t *testing.T, f *settlementFixture, now func() time.Time) *stripesync.Projector {
	t.Helper()
	p, err := stripesync.NewProjector(stripesync.ProjectorOptions{
		Inbox: inbox.New(), Orders: orders.New(), Billing: billing.New(),
		Customers: customers.New(),
		Pool:      f.pool, Pay: f.pay, Environment: core.StripeSandbox, Now: now,
	})
	if err != nil {
		t.Fatalf("NewProjector: %v", err)
	}
	return p
}

// drainWith drains every claimable event with the given projector, tolerating
// projection errors: a failed event is rescheduled, which is itself behavior
// under test here.
func drainWith(t *testing.T, p *stripesync.Projector, rounds int) {
	t.Helper()
	for range rounds {
		worked, err := p.ProcessOne(context.Background(), time.Minute)
		if err != nil {
			continue
		}
		if !worked {
			return
		}
	}
}

// newSubscriptionID mints a unique subscription id and registers the cleanups
// every cross-object test needs.
func newSubscriptionID(t *testing.T, f *settlementFixture) string {
	t.Helper()
	subscriptionID := "sub_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM stripe_projection_applications WHERE object_id = $1`, subscriptionID)
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM staff_alerts WHERE source_key = $1`, "subscription:"+subscriptionID)
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM staff_alerts WHERE source_key = $1`, "order:"+f.orderID.String())
	})
	return subscriptionID
}

// The reported interleaving: settlement reads the subscription, pauses; Stripe
// cancels it; the lifecycle event is fully processed — it finds no membership
// and no settled order, records the benign first-invoice signal, and commits;
// settlement then resumes holding a canonical read from before the
// cancellation.
//
// The failure this proves absent: settlement used to take the unrelated Session
// lock, pass a freshness check that only knew about Session observations, and
// insert an ACTIVE membership from its stale read — while the cancellation was
// already recorded as applied, so nothing would ever arrive to repair it. The
// member kept access forever on a subscription Stripe had already deleted.
//
// Against the pre-fix code the final membership reads "active" and this fails.
func TestSettlementPausedAcrossANewerCancellationCannotGrantStaleAccess(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()
	subscriptionID := newSubscriptionID(t, f)

	f.fake.SettleSession(f.sessionID, "pi_"+subscriptionID, subscriptionID)
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)

	// Hold settlement between its canonical reads and its transaction.
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
	settled := make(chan error, 1)
	go func() {
		_, err := f.projector.ProcessOne(ctx, time.Minute)
		settled <- err
	}()
	<-paused

	// While settlement holds its stale read: Stripe cancels, delivers the
	// lifecycle event, and another worker projects it to completion. No
	// membership and no settled order exist yet, so this records the benign
	// signal — the quiet path the live gate observed for real.
	f.fake.CancelSubscription(subscriptionID)
	f.receive(t, "customer.subscription.deleted", subscriptionID, core.Memberships)
	other := projectorWith(t, f, nil)
	drainWith(t, other, 4)
	if signals := f.signalsFor(t, subscriptionID); !contains(signals, "no membership yet; initial settlement not processed") {
		t.Fatalf("the lifecycle event did not record its benign signal; signals=%v", signals)
	}

	// Resume. The fixed code refuses to grant from the superseded read — the
	// event fails and is rescheduled — and the retry re-retrieves the
	// subscription as Stripe now holds it. The future clock is only to skip
	// the retry backoff.
	close(resume)
	<-settled
	retry := projectorWith(t, f, func() time.Time { return time.Now().UTC().Add(2 * time.Hour) })
	drainWith(t, retry, 6)

	// The money settled, exactly once.
	if got := f.orderState(t); got != "paid" {
		t.Fatalf("order state = %s, want paid: the retry must still settle the money", got)
	}
	var paidTransitions int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM order_state_history WHERE order_id = $1 AND to_state = 'paid'
	`, f.orderID).Scan(&paidTransitions); err != nil {
		t.Fatalf("count transitions: %v", err)
	}
	if paidTransitions != 1 {
		t.Errorf("%d paid transitions, want exactly 1", paidTransitions)
	}

	// THE assertion: the membership reflects the newest canonical state, not
	// the read settlement was holding when it paused.
	status, _, _ := membershipState(t, f)
	if status != "canceled" {
		t.Errorf("membership status = %s, want canceled: settlement granted access "+
			"from a canonical subscription read that a newer cancellation had already superseded", status)
	}

	// Both events left application evidence, and nobody was paged.
	if signals := f.signalsFor(t, f.sessionID); !contains(signals, "order settled") {
		t.Errorf("session signals %v do not record the settlement", signals)
	}
	if signals := f.signalsFor(t, subscriptionID); !contains(signals, "order settled") {
		t.Errorf("subscription signals %v do not record settlement's observation — "+
			"without it, a stale lifecycle event could still overwrite this membership", signals)
	}
	var alerts int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM staff_alerts WHERE source_key IN ($1, $2)
	`, "order:"+f.orderID.String(), "subscription:"+subscriptionID).Scan(&alerts); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alerts != 0 {
		t.Errorf("%d staff alerts for an ordinary race the projector is supposed to absorb", alerts)
	}
}

// The same race mirrored: the lifecycle path holds the stale read. It retrieves
// the subscription before Stripe records the member's cancellation request,
// pauses; settlement then completes with a fresher read that carries
// cancel_at_period_end; the lifecycle event resumes holding state from before.
//
// Pre-fix, its freshness guard asked about Subscription observations and
// settlement had recorded none — settlement's evidence lived only under the
// Session's object id — so the stale update applied and switched
// cancel_at_period_end back off: a cancellation Stripe already accepted,
// silently forgotten, and the member renews forever. Against the pre-fix code
// the final membership reads cancel_at_period_end=false and this fails.
func TestLifecyclePausedAcrossANewerSettlementCannotMoveTheMembershipBackwards(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := newSubscriptionID(t, f)

	f.fake.SettleSession(f.sessionID, "pi_"+subscriptionID, subscriptionID)

	// The lifecycle event arrives first — Stripe promises no order — and its
	// worker pauses after reading the subscription as it stands now: active,
	// not scheduled to cancel.
	f.receive(t, "customer.subscription.updated", subscriptionID, core.Memberships)
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.projector.SetPauseBeforeTxForTest(func(e inbox.Event) {
		if e.Type != "customer.subscription.updated" {
			return
		}
		once.Do(func() {
			close(paused)
			<-resume
		})
	})
	lifecycle := make(chan error, 1)
	go func() {
		_, err := f.projector.ProcessOne(context.Background(), time.Minute)
		lifecycle <- err
	}()
	<-paused

	// The member schedules their cancellation, and settlement — reading the
	// subscription fresh — completes and records a membership that will not
	// renew.
	f.fake.ScheduleCancellation(subscriptionID)
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	other := projectorWith(t, f, nil)
	drainWith(t, other, 4)
	if got := f.orderState(t); got != "paid" {
		t.Fatalf("order state = %s; settlement should have completed while the lifecycle event was paused", got)
	}
	if _, _, cancelAtPeriodEnd := membershipState(t, f); !cancelAtPeriodEnd {
		t.Fatal("settlement did not record the scheduled cancellation; this test would prove nothing")
	}

	// Resume the lifecycle event, still holding its pre-cancellation read.
	close(resume)
	if err := <-lifecycle; err != nil {
		t.Fatalf("the superseded lifecycle event must be refused quietly, not failed: %v", err)
	}

	if _, _, cancelAtPeriodEnd := membershipState(t, f); !cancelAtPeriodEnd {
		t.Error("a stale lifecycle observation switched cancel_at_period_end back off: " +
			"the member's accepted cancellation was silently forgotten")
	}
	if signals := f.signalsFor(t, subscriptionID); !contains(signals, "superseded by a newer observation") {
		t.Errorf("subscription signals %v do not record the refusal", signals)
	}
}
