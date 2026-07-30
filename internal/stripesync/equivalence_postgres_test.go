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

// mismatchAlert reads the alert raised for this fixture's order, if any.
func mismatchAlert(t *testing.T, f *settlementFixture) (count int, message string) {
	t.Helper()
	err := f.pool.Conn().QueryRow(context.Background(), `
		SELECT count(*), COALESCE(max(message), '')
		FROM staff_alerts WHERE source_key = $1 AND kind = 'settlement_amount_mismatch'
	`, "order:"+f.orderID.String()).Scan(&count, &message)
	if err != nil {
		t.Fatalf("read alert: %v", err)
	}
	return count, message
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
}

// The custom-amount Friends path is the one place a member chooses the number,
// so it is the one place the comparison could be systematically wrong. The
// session carries an inline price rather than a catalog price id, and the totals
// must still line up.
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
}
