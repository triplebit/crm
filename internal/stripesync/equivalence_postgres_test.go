package stripesync_test

import (
	"context"
	"strings"
	"testing"

	"triplebit.org/portal/internal/core"
)

// The settlement money comparison: what Stripe charged must equal what the order
// froze, or nothing is granted.
//
// Before this existed the projector retrieved the canonical session from Stripe
// and then settled on payment_status == paid alone, comparing none of the money
// it had just read. The re-read was described in commit messages as an integrity
// control; it compared nothing. Nor could a test have noticed, because the fake
// hardcoded amount_total to zero — so these tests needed the fake to learn how to
// total line items before they could exist at all.

// mismatchAlert reads the money alert raised for this fixture's order, if any.
func mismatchAlert(t *testing.T, f *settlementFixture) (count int, message string) {
	t.Helper()
	return alertOfKind(t, f, "settlement_amount_mismatch")
}

// identityAlert reads the identity alert raised for this fixture's order.
func identityAlert(t *testing.T, f *settlementFixture) (count int, message string) {
	t.Helper()
	return alertOfKind(t, f, "settlement_identity_mismatch")
}

func alertOfKind(t *testing.T, f *settlementFixture, kind string) (count int, message string) {
	t.Helper()
	err := f.pool.Conn().QueryRow(context.Background(), `
		SELECT count(*), COALESCE(max(message), '')
		FROM staff_alerts WHERE source_key = $1 AND kind = $2
	`, "order:"+f.orderID.String(), kind).Scan(&count, &message)
	if err != nil {
		t.Fatalf("read alert: %v", err)
	}
	return count, message
}

// refusedEverything asserts the fail-closed outcome every equivalence mismatch
// shares: the order did not settle, and no membership was granted.
func refusedEverything(t *testing.T, f *settlementFixture) {
	t.Helper()
	if got := f.orderState(t); got != "checkout_pending" {
		t.Errorf("order state = %s: a mismatched settlement must not settle", got)
	}
	var memberships int
	if err := f.pool.Conn().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE user_id = $1`, f.person.UserID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberships != 0 {
		t.Error("a membership was granted despite the mismatch")
	}
}

// cleanupAlerts removes the alerts a test raised. The error is reported rather
// than discarded: a silently failing cleanup DELETE is how this project leaked
// rows into the shared database for weeks before anybody counted them.
func cleanupAlerts(t *testing.T, f *settlementFixture) {
	t.Cleanup(func() {
		if _, err := f.pool.Conn().Exec(context.Background(),
			`DELETE FROM staff_alerts WHERE source_key = $1`,
			"order:"+f.orderID.String()); err != nil {
			t.Errorf("cleanup alerts for order %s: %v", f.orderID, err)
		}
	})
}

// A charge for the wrong amount settles nothing and pages a human. This is the
// case that matters: a member charged an amount nobody agreed to must not receive
// a membership on the strength of it.
func TestSettlementRefusesAWrongAmount(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_wrongamount", "sub_wrongamount")
	// Stripe now claims a different total than the order's frozen lines. Nothing
	// in the portal can produce this, which is the point: the check exists for
	// the case where the impossible has happened.
	if !f.fake.SetSessionAmountTotal(f.sessionID, 999999, "") {
		t.Fatal("the fake does not know this session")
	}
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	if got := f.orderState(t); got != "checkout_pending" {
		t.Errorf("order state = %s: a mismatched charge must not settle", got)
	}
	var memberships int
	if err := f.pool.Conn().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE user_id = $1`, f.person.UserID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberships != 0 {
		t.Error("a membership was granted for a charge that does not match the order")
	}

	count, message := mismatchAlert(t, f)
	if count == 0 {
		t.Fatalf("no alert was raised; signals=%v", f.signalsFor(t, f.sessionID))
	}
	// The alert has to be actionable without opening a debugger: the numbers, and
	// what the reader is expected to do about them.
	for _, want := range []string{"999999", "NOT settled", "refund"} {
		if !strings.Contains(message, want) {
			t.Errorf("alert message does not mention %q: %s", want, message)
		}
	}
}

// A charge in the wrong currency is refused too. Amount alone is not enough:
// 15000 JPY and 15000 USD are the same integer and very different money.
func TestSettlementRefusesAWrongCurrency(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_wrongcurrency", "sub_wrongcurrency")
	// Same total, different currency.
	total := f.sessionTotal(t)
	if !f.fake.SetSessionAmountTotal(f.sessionID, total, "jpy") {
		t.Fatal("the fake does not know this session")
	}
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	if got := f.orderState(t); got != "checkout_pending" {
		t.Errorf("order state = %s: a foreign-currency charge must not settle", got)
	}
	if count, message := mismatchAlert(t, f); count == 0 {
		t.Error("no alert for a currency mismatch")
	} else if !strings.Contains(message, "jpy") {
		t.Errorf("alert does not name the currency: %s", message)
	}
}

// And the control that stops this from being a test of nothing: an honest
// settlement, where Stripe and the order agree, must still go through. A check
// that refused everything would satisfy both tests above.
//
// This is also the positive control for the identity checks: the session's
// customer is the member's recorded one, the subscription belongs to that same
// customer, and the subscription's price is the exact catalog price the frozen
// tier line sold — the normal case, which must never page anyone.
func TestSettlementAcceptsAMatchingCharge(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_matching", "sub_matching")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	if got := f.orderState(t); got != "paid" {
		t.Errorf("order state = %s: a matching charge must settle", got)
	}
	if count, _ := mismatchAlert(t, f); count != 0 {
		t.Error("a matching charge raised a mismatch alert")
	}
	if count, message := identityAlert(t, f); count != 0 {
		t.Errorf("a matching settlement raised an identity alert: %s", message)
	}
}

// The recurring terms must be the exact catalog price the member agreed to, not
// merely the same amount. A subscription on a different price settles the same
// money today and renews on terms nobody froze tomorrow — which is why amount
// equality cannot stand in for price identity.
func TestSettlementRefusesAWrongSubscriptionPrice(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_wrongprice", "sub_wrongprice")
	// Stripe now reports the subscription on a different price. The session's
	// amount_total is untouched, so the money comparison alone cannot see this.
	if !f.fake.SetSubscriptionPrice("sub_wrongprice", "price_imposter") {
		t.Fatal("the fake does not know this subscription")
	}
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	refusedEverything(t, f)
	count, message := identityAlert(t, f)
	if count == 0 {
		t.Fatalf("no identity alert for a wrong subscription price; signals=%v", f.signalsFor(t, f.sessionID))
	}
	for _, want := range []string{"price_imposter", "NOT settled", "refund"} {
		if !strings.Contains(message, want) {
			t.Errorf("alert message does not mention %q: %s", want, message)
		}
	}
}

// The subscription must belong to the same customer as the session that sold
// it, or renewals and cancellation are bound to somebody else's Stripe identity
// while this member holds the access.
func TestSettlementRefusesAWrongSubscriptionCustomer(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_wrongsubcust", "sub_wrongsubcust")
	if !f.fake.SetSubscriptionCustomer("sub_wrongsubcust", "cus_somebodyelse") {
		t.Fatal("the fake does not know this subscription")
	}
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	refusedEverything(t, f)
	count, message := identityAlert(t, f)
	if count == 0 {
		t.Fatalf("no identity alert for a wrong subscription customer; signals=%v", f.signalsFor(t, f.sessionID))
	}
	if !strings.Contains(message, "cus_somebodyelse") {
		t.Errorf("alert does not name the intruding customer: %s", message)
	}
}

// The session's payer must be the customer this portal recorded for the member
// when it created the checkout. Any other customer is someone else's payment
// wearing this order's reference — and it must not buy this member access.
func TestSettlementRefusesASessionPaidByAnotherCustomer(t *testing.T) {
	f := newSettlement(t, "hotspot")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_wrongsesscust", "sub_wrongsesscust")
	if !f.fake.SetSessionCustomer(f.sessionID, "cus_stranger") {
		t.Fatal("the fake does not know this session")
	}
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	refusedEverything(t, f)
	count, message := identityAlert(t, f)
	if count == 0 {
		t.Fatalf("no identity alert for a wrong session customer; signals=%v", f.signalsFor(t, f.sessionID))
	}
	if !strings.Contains(message, "cus_stranger") {
		t.Errorf("alert does not name the unexpected customer: %s", message)
	}
}

// The custom-amount Friends path is the one place a member chooses the number,
// so it is the one place the comparison could be systematically wrong. The
// session carries an inline price rather than a catalog price id, and the totals
// must still line up.
//
// It is also the positive control for the identity rule's one deliberate gap:
// Stripe mints an ad-hoc Price for inline price_data, whose id nothing local
// ever stored, so the subscription-price comparison is defined as vacuous for
// a custom line — while the customer checks still apply in full. A check that
// naively demanded price equality here would refuse every custom donation.
func TestCustomFriendsAmountMatchesItsSession(t *testing.T) {
	f := newSettlement(t, "friends-custom")
	cleanupAlerts(t, f)

	f.fake.SettleSession(f.sessionID, "pi_customfriends", "sub_customfriends")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Donations)
	f.drain(t)

	if got := f.orderState(t); got != "paid" {
		t.Errorf("order state = %s: a member-chosen amount must settle against itself", got)
	}
	if count, message := mismatchAlert(t, f); count != 0 {
		t.Errorf("a member's own chosen amount was refused: %s", message)
	}
	if count, message := identityAlert(t, f); count != 0 {
		t.Errorf("the ad-hoc inline price was treated as an identity mismatch: %s", message)
	}
}
