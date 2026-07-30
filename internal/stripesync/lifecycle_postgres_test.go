package stripesync_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
)

// The recurring lifecycle, which M6 claimed and did not have.
//
// Every test here would have passed vacuously before, because invoice.paid and
// the subscription events resolved to nothing and were recorded as handled. The
// member-visible consequences were that a paying member lost access at the end of
// their first period, and a cancelled member kept it forever.

// membershipState reads the columns Stripe owns the truth about.
func membershipState(t *testing.T, f *settlementFixture) (status string, periodEnd *time.Time, cancelAtPeriodEnd bool) {
	t.Helper()
	err := f.pool.Conn().QueryRow(context.Background(), `
		SELECT status, current_period_end, cancel_at_period_end
		FROM memberships WHERE user_id = $1
	`, f.person.UserID).Scan(&status, &periodEnd, &cancelAtPeriodEnd)
	if err != nil {
		t.Fatalf("read membership: %v", err)
	}
	return status, periodEnd, cancelAtPeriodEnd
}

// settledMembership drives a hotspot order to paid so there is a membership for
// the lifecycle to act on, and returns the subscription id it settled against.
//
// The id is unique per run, and that is not cosmetic: these tests share one
// PostgreSQL with every other package, and stripe_projection_applications is
// never truncated. A fixed id like subscriptionID inherits the previous run's
// observations — which broke the shuffled-delivery test on its second run, the
// ordering guard correctly refusing an event because an hour-in-the-future
// observation from the last run was still on record.
func settledMembership(t *testing.T, f *settlementFixture) string {
	t.Helper()
	subscriptionID := "sub_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM stripe_projection_applications WHERE object_id = $1`, subscriptionID)
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM staff_alerts WHERE source_key = $1`, "subscription:"+subscriptionID)
	})

	f.fake.SettleSession(f.sessionID, "pi_"+subscriptionID, subscriptionID)
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)
	if got := f.orderState(t); got != "paid" {
		t.Fatalf("order state = %s after settlement; the lifecycle tests need a membership", got)
	}
	return subscriptionID
}

// A renewal must move the period forward. This is the one that matters most: a
// membership whose period end never advances expires while the member is still
// being charged.
func TestRenewalAdvancesTheMembershipPeriod(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := settledMembership(t, f)

	_, firstEnd, _ := membershipState(t, f)
	if firstEnd == nil {
		t.Fatal("settlement recorded no period end, so there is nothing to advance")
	}

	// Stripe renews: a new period, and invoice.paid announcing it. Note there is
	// NO checkout.session event — that is the whole point.
	renewedTo := firstEnd.Add(30 * 24 * time.Hour)
	if !f.fake.RenewSubscription(subscriptionID, renewedTo) {
		t.Fatal("the fake does not know this subscription")
	}
	f.receiveInvoice(t, "invoice.paid", "in_"+subscriptionID, subscriptionID, core.Memberships)
	f.drain(t)

	status, secondEnd, _ := membershipState(t, f)
	if secondEnd == nil {
		t.Fatal("the membership lost its period end")
	}
	if !secondEnd.After(*firstEnd) {
		t.Errorf("period end did not advance: %s then %s — a paying member would lose access",
			firstEnd.Format(time.RFC3339), secondEnd.Format(time.RFC3339))
	}
	if status != "active" {
		t.Errorf("status = %s after a paid renewal, want active", status)
	}
}

// Deletion must revoke. Until this worked, cancelling bought permanent access.
func TestSubscriptionDeletionRevokesTheMembership(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := settledMembership(t, f)

	if status, _, _ := membershipState(t, f); status != "active" {
		t.Fatalf("membership starts %s, not active; this test would prove nothing", status)
	}

	f.fake.CancelSubscription(subscriptionID)
	f.receive(t, "customer.subscription.deleted", subscriptionID, core.Memberships)
	f.drain(t)

	status, _, _ := membershipState(t, f)
	if status != "canceled" {
		t.Errorf("status = %s after deletion, want canceled: access is not revoked", status)
	}
}

// Cancel-at-period-end is not cancellation: the member keeps access until the
// period runs out. Conflating the two either cuts someone off early or never.
func TestScheduledCancellationIsRecordedWithoutRevoking(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := settledMembership(t, f)

	f.fake.ScheduleCancellation(subscriptionID)
	f.receive(t, "customer.subscription.updated", subscriptionID, core.Memberships)
	f.drain(t)

	status, periodEnd, cancelAtPeriodEnd := membershipState(t, f)
	if !cancelAtPeriodEnd {
		t.Error("cancel_at_period_end was not recorded; nothing will stop the renewal")
	}
	if status != "active" {
		t.Errorf("status = %s, want active: a scheduled cancellation must not revoke early", status)
	}
	if periodEnd == nil {
		t.Error("the period end was lost, so access has no expiry")
	}
}

// A dunning status must reach the membership, or a failed card looks like a
// healthy member.
func TestPastDueStatusReachesTheMembership(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := settledMembership(t, f)

	f.fake.SetSubscriptionStatus(subscriptionID, "past_due")
	f.receive(t, "customer.subscription.updated", subscriptionID, core.Memberships)
	f.drain(t)

	if status, _, _ := membershipState(t, f); status != "past_due" {
		t.Errorf("status = %s, want past_due", status)
	}
}

// The ordinary race, which must be silent: Stripe sends the first invoice and the
// checkout session together and the invoice is processed first. Nothing is lost,
// because settlement reads canonical subscription state — so this must NOT alert.
func TestFirstInvoiceArrivingBeforeSettlementIsNotAnAlert(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()

	// Give the fake a subscription without settling the order, so the invoice can
	// be projected while no membership exists yet.
	subscriptionID := "sub_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM stripe_projection_applications WHERE object_id = $1`, subscriptionID)
	})
	f.fake.SettleSession(f.sessionID, "pi_"+subscriptionID, subscriptionID)
	f.receiveInvoice(t, "invoice.paid", "in_"+subscriptionID, subscriptionID, core.Memberships)
	f.drain(t)

	var alerts int
	if err := f.pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM staff_alerts WHERE source_key = $1`,
		"subscription:"+subscriptionID).Scan(&alerts); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alerts != 0 {
		t.Error("an ordinary first-invoice race paged a human")
	}
	if signals := f.signalsFor(t, subscriptionID); !contains(signals, "no membership yet; initial settlement not processed") {
		t.Errorf("signals %v do not record the benign race", signals)
	}

	// And settlement afterwards still produces the membership with a period.
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)
	if _, periodEnd, _ := membershipState(t, f); periodEnd == nil {
		t.Error("settlement after the early invoice left the membership with no period end")
	}
}

// The serious case: an order IS settled against the subscription and there is
// still no membership. Money moved and nothing was granted, which is the exact
// failure this milestone exists to prevent, so it must page somebody.
func TestSettledSubscriptionWithNoMembershipRaisesAnAlert(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()
	subscriptionID := settledMembership(t, f)

	// Delete the membership behind the projector's back, leaving the settled
	// order pointing at a subscription with nothing projected for it.
	if _, err := f.pool.Conn().Exec(ctx,
		`DELETE FROM memberships WHERE user_id = $1`, f.person.UserID); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	f.fake.RenewSubscription(subscriptionID, time.Now().Add(30*24*time.Hour))
	f.receiveInvoice(t, "invoice.paid", "in_"+subscriptionID, subscriptionID, core.Memberships)
	f.drain(t)

	var alerts int
	var message string
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*), COALESCE(max(message), '')
		FROM staff_alerts WHERE source_key = $1
	`, "subscription:"+subscriptionID).Scan(&alerts, &message); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alerts == 0 {
		t.Fatalf("a paid subscription with no membership did not raise an alert; signals=%v",
			f.signalsFor(t, subscriptionID))
	}
	if message == "" {
		t.Error("the alert carries no cause")
	}
}

// Duplicate and shuffled delivery: Stripe retries, and a later event can arrive
// before an earlier one. Neither may move a membership backwards.
func TestShuffledLifecycleDeliveryDoesNotMoveTheMembershipBackwards(t *testing.T) {
	f := newSettlement(t, "hotspot")
	subscriptionID := settledMembership(t, f)

	// Cancel, project, then deliver an older "active" observation afterwards.
	f.fake.CancelSubscription(subscriptionID)
	f.receive(t, "customer.subscription.deleted", subscriptionID, core.Memberships)
	f.drain(t)
	if status, _, _ := membershipState(t, f); status != "canceled" {
		t.Fatalf("status = %s, expected canceled before the shuffle", status)
	}

	// The stale event: the fake now reports active again, but an observation from
	// the future is already on record, so the guard must refuse to apply this one.
	// Seeding the future observation is how the existing session-path test
	// expresses the same idea; retrieval times are real clock reads, so they
	// cannot be ordered any other way.
	f.seedFutureObservation(t, subscriptionID, "customer.subscription.updated")
	f.fake.SetSubscriptionStatus(subscriptionID, "active")
	f.receive(t, "customer.subscription.updated", subscriptionID, core.Memberships)
	f.drain(t)

	if status, _, _ := membershipState(t, f); status != "canceled" {
		t.Errorf("status = %s: a superseded observation resurrected a cancelled membership", status)
	}
	if signals := f.signalsFor(t, subscriptionID); !contains(signals, "superseded by a newer observation") {
		t.Errorf("signals %v do not record the refusal", signals)
	}
}
