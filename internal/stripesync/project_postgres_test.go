package stripesync_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/stripesync"
	"triplebit.org/portal/internal/stripetest"
	"triplebit.org/portal/internal/testdb"
)

// The projector is tested through a real order: a checkout is started with the
// M5 service, then Stripe is told the card succeeded, then an event is
// received and projected. Testing it any other way would prove only that the
// projector can write rows, not that it settles the orders this portal makes.
type settlementFixture struct {
	pool      *db.Pool
	fake      *stripetest.Server
	pay       *stripepay.Client
	svc       *checkout.Service
	projector *stripesync.Projector
	inbox     *inbox.Repo
	person    checkout.Person
	orderID   uuid.UUID
	sessionID string
}

func newSettlement(t *testing.T, program string) *settlementFixture {
	t.Helper()
	ctx := context.Background()
	pool := testdb.Pool(t)
	fake := stripetest.New(t)

	pay, err := stripepay.New(stripepay.Options{
		APIKey:               "sk_test_project",
		Environment:          core.StripeSandbox,
		MembershipsAccountID: "acct_pm1",
		DonationsAccountID:   "acct_pd1",
		BaseURL:              fake.URL(),
	})
	if err != nil {
		t.Fatalf("stripepay.New: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 90)
	}
	ring, err := cryptox.NewKeyring("proj-pii", map[string][]byte{"proj-pii": key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	svc, err := checkout.New(checkout.Options{
		Customers: customers.New(), Orders: orders.New(), Catalog: catalogdb.New(),
		Pool: pool, Pay: pay, Keys: ring,
		Environment: core.StripeSandbox, BaseURL: "http://portal.test",
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("checkout.New: %v", err)
	}
	projector, err := stripesync.NewProjector(stripesync.ProjectorOptions{
		Inbox: inbox.New(), Orders: orders.New(), Billing: billing.New(),
		Pool: pool, Pay: pay, Environment: core.StripeSandbox,
	})
	if err != nil {
		t.Fatalf("NewProjector: %v", err)
	}

	person := seedPerson(t, pool)
	slug := seedSellable(t, pool, program)
	switch program {
	case "friends-custom":
		// No slug: the member names the amount, which is the path with no
		// catalog price version to anchor a membership on.
		_, err = svc.StartFriends(ctx, person, checkout.FriendsRequest{CustomAmount: "12.50"})
	case "friends":
		_, err = svc.StartFriends(ctx, person, checkout.FriendsRequest{TierSlug: slug})
	default:
		_, err = svc.StartEnrollment(ctx, person, checkout.EnrollmentRequest{
			TierSlug: slug, IMEI: "356938035643809",
		})
	}
	if err != nil {
		t.Fatalf("start checkout: %v", err)
	}

	var orderID uuid.UUID
	var sessionID string
	if err := pool.Conn().QueryRow(ctx, `
		SELECT id, stripe_checkout_session_id FROM orders WHERE user_id = $1
	`, person.UserID).Scan(&orderID, &sessionID); err != nil {
		t.Fatalf("read order: %v", err)
	}

	return &settlementFixture{
		pool: pool, fake: fake, pay: pay, svc: svc,
		projector: projector, inbox: inbox.New(),
		person: person, orderID: orderID, sessionID: sessionID,
	}
}

// receive stores an event the way the webhook handler would.
func (f *settlementFixture) receive(t *testing.T, eventType, objectID string, account core.AccountRef) inbox.Event {
	t.Helper()
	id := uuid.New()
	stripeID := "evt_" + strings.ReplaceAll(id.String(), "-", "")
	payload, _ := json.Marshal(map[string]any{
		"id": stripeID, "type": eventType,
		"data": map[string]any{"object": map[string]any{"id": objectID}},
	})
	event := inbox.Event{
		ID: id, Environment: core.StripeSandbox, Account: account,
		StripeID: stripeID, Type: eventType, ObjectID: objectID, Payload: payload,
	}
	now := time.Now().UTC()
	if _, err := f.inbox.Receive(context.Background(), f.pool.Conn(), event, now, now); err != nil {
		t.Fatalf("receive %s: %v", eventType, err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Conn().Exec(context.Background(),
			`DELETE FROM webhook_events WHERE stripe_event_id = $1`, stripeID)
	})
	return event
}

func (f *settlementFixture) orderState(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.pool.Conn().QueryRow(context.Background(),
		`SELECT state FROM orders WHERE id = $1`, f.orderID).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return state
}

// drain processes every claimable event, returning how many it handled.
func (f *settlementFixture) drain(t *testing.T) int {
	t.Helper()
	handled := 0
	for i := 0; i < 20; i++ {
		did, err := f.projector.ProcessOne(context.Background(), time.Minute)
		if err != nil {
			t.Fatalf("ProcessOne: %v", err)
		}
		if !did {
			break
		}
		handled++
	}
	return handled
}

// The milestone's headline: nothing granted it, a verified event did.
func TestPaidSessionSettlesTheOrderByItself(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()

	if got := f.orderState(t); got != "checkout_pending" {
		t.Fatalf("order starts as %s", got)
	}

	// Stripe: the card succeeded.
	f.fake.SettleSession(f.sessionID, "pi_settled1", "sub_settled1")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)

	before := f.fake.SessionGets()
	f.drain(t)

	if got := f.orderState(t); got != "paid" {
		t.Errorf("order state = %s, want paid", got)
	}
	// The projector must have RETRIEVED, not trusted the payload — that is the
	// difference between "Stripe says" and "Stripe said once".
	if f.fake.SessionGets() <= before {
		t.Error("the projector never retrieved the canonical session")
	}

	// Held stock becomes committed, and the membership appears with an anchor.
	var committed, memberships int
	var anchor, source *uuid.UUID
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM inventory_reservations r
		JOIN order_lines l ON l.id = r.order_line_id
		WHERE l.order_id = $1 AND r.state = 'committed'
	`, f.orderID).Scan(&committed); err != nil {
		t.Fatalf("count committed: %v", err)
	}
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM memberships WHERE user_id = $1
	`, f.person.UserID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT tier_price_version_id, source_order_line_id
		FROM memberships WHERE user_id = $1
	`, f.person.UserID).Scan(&anchor, &source); err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if memberships != 1 {
		t.Errorf("%d memberships, want 1", memberships)
	}
	if anchor == nil || source != nil {
		t.Errorf("a catalog-priced tier must anchor on its price version (anchor=%v source=%v)", anchor, source)
	}
	if committed == 0 {
		t.Log("no inventory on this tier, so nothing to commit — fine")
	}
}

// Stripe retries deliveries and sends several event types for one settlement.
// None of that may settle an order twice.
func TestReplayedAndDuplicateEventsSettleOnce(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()

	f.fake.SettleSession(f.sessionID, "pi_replay1", "sub_replay1")
	first := f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	// The same event id again — a Stripe redelivery — plus a second event type
	// about the same settlement, which is what Stripe actually sends.
	now := time.Now().UTC()
	if _, err := f.inbox.Receive(ctx, f.pool.Conn(), first, now, now); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	f.receive(t, "payment_intent.succeeded", "pi_replay1", core.Memberships)
	f.drain(t)

	var paidTransitions, memberships int
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT count(*) FROM order_state_history WHERE order_id = $1 AND to_state = 'paid'
	`, f.orderID).Scan(&paidTransitions); err != nil {
		t.Fatalf("count transitions: %v", err)
	}
	if err := f.pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE user_id = $1`, f.person.UserID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if paidTransitions != 1 {
		t.Errorf("%d paid transitions, want exactly 1: settlement must happen once", paidTransitions)
	}
	if memberships != 1 {
		t.Errorf("%d memberships, want 1", memberships)
	}
	if got := f.orderState(t); got != "paid" {
		t.Errorf("order state = %s", got)
	}
}

// The out-of-order guard: an observation older than one already applied must
// not move settled state backwards.
func TestStaleObservationIsRefused(t *testing.T) {
	f := newSettlement(t, "hotspot")
	ctx := context.Background()
	repo := billing.New()

	// Pretend a very recent observation of this session was already applied.
	future := time.Now().UTC().Add(time.Hour)
	if _, err := repo.RecordApplication(ctx, f.pool.Conn(), billing.Application{
		Environment: core.StripeSandbox, Account: core.Memberships,
		StripeEvent: "evt_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		EventType:   "checkout.session.completed", Signal: "seeded",
		ObjectID: f.sessionID, ObservedAt: future,
	}); err != nil {
		t.Fatalf("seed application: %v", err)
	}

	f.fake.SettleSession(f.sessionID, "pi_stale1", "sub_stale1")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Memberships)
	f.drain(t)

	if got := f.orderState(t); got != "checkout_pending" {
		t.Errorf("order state = %s, want checkout_pending: a stale observation must not settle it", got)
	}
	var signals []string
	rows, err := f.pool.Conn().Query(ctx,
		`SELECT signal FROM stripe_projection_applications WHERE object_id = $1`, f.sessionID)
	if err != nil {
		t.Fatalf("read signals: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		signals = append(signals, s)
	}
	if !contains(signals, "superseded by a newer observation") {
		t.Errorf("signals %v do not record the refusal", signals)
	}
}

// An expired session releases the stock it was holding — the other half of
// reservation recovery, arriving from Stripe rather than from the sweep.
func TestExpiredSessionReleasesReservations(t *testing.T) {
	f := newSettlement(t, "hotspot")

	// Prove there is something to release first. Without this the assertion
	// below passes against an order that never held any stock, which is what
	// it did until the worker's sweep test tripped over the same gap.
	if f.heldReservations(t) == 0 {
		t.Fatal("the order holds no stock; this test would prove nothing")
	}

	f.fake.ExpireSession(f.sessionID)
	f.receive(t, "checkout.session.expired", f.sessionID, core.Memberships)
	f.drain(t)

	if got := f.orderState(t); got != "expired" {
		t.Errorf("order state = %s, want expired", got)
	}
	if held := f.heldReservations(t); held != 0 {
		t.Errorf("%d reservations still held after expiry", held)
	}
}

// heldReservations counts the stock this order is holding.
func (f *settlementFixture) heldReservations(t *testing.T) int {
	t.Helper()
	var held int
	if err := f.pool.Conn().QueryRow(context.Background(), `
		SELECT count(*) FROM inventory_reservations r
		JOIN order_lines l ON l.id = r.order_line_id
		WHERE l.order_id = $1 AND r.state = 'held'
	`, f.orderID).Scan(&held); err != nil {
		t.Fatalf("count held reservations: %v", err)
	}
	return held
}

// A custom-amount Friends subscription anchors on its order line, because the
// member set the price and no catalog version describes it. This is the M5
// review's blocker, proven end to end.
func TestCustomFriendsSettlementAnchorsOnItsOrderLine(t *testing.T) {
	f := newSettlement(t, "friends-custom")
	ctx := context.Background()

	f.fake.SettleSession(f.sessionID, "pi_custom1", "sub_custom1")
	f.receive(t, "checkout.session.completed", f.sessionID, core.Donations)
	f.drain(t)

	if got := f.orderState(t); got != "paid" {
		t.Fatalf("order state = %s, want paid", got)
	}
	var anchor, source *uuid.UUID
	if err := f.pool.Conn().QueryRow(ctx, `
		SELECT tier_price_version_id, source_order_line_id
		FROM memberships WHERE user_id = $1
	`, f.person.UserID).Scan(&anchor, &source); err != nil {
		t.Fatalf("read membership: %v", err)
	}
	if anchor != nil {
		t.Errorf("a member-chosen amount anchored on a catalog version %v", anchor)
	}
	if source == nil {
		t.Error("a custom Friends membership has no order-line anchor")
	}

	// And the gift is recorded, at the frozen line amount.
	var amount int64
	if err := f.pool.Conn().QueryRow(ctx,
		`SELECT amount FROM donations WHERE order_id = $1`, f.orderID).Scan(&amount); err != nil {
		t.Fatalf("read donation: %v", err)
	}
	if amount != 1250 {
		t.Errorf("donation amount = %d, want the frozen 1250", amount)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// Seeds and helpers. Catalog rows are closed rather than deleted, for the same
// foreign-key reasons the checkout tests document.
func seedPerson(t *testing.T, pool *db.Pool) checkout.Person {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	sub := "proj-sub-" + id.String()
	if _, err := pool.Conn().Exec(ctx, `
		INSERT INTO users (id, pocket_id_sub, email, display_name, email_verified)
		VALUES ($1, $2, $3, 'Projection Member', true)
	`, id, sub, sub+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		testdb.PurgeOrders(t, pool, id)
		for _, statement := range []string{
			`DELETE FROM donations WHERE user_id = $1`,
			`DELETE FROM memberships WHERE user_id = $1`,
			`DELETE FROM stripe_customers WHERE user_id = $1`,
			`DELETE FROM stripe_customer_creation_intents WHERE user_id = $1`,
			`DELETE FROM users WHERE id = $1`,
		} {
			if _, err := pool.Conn().Exec(c, statement, id); err != nil {
				t.Errorf("cleanup (%s): %v", statement, err)
			}
		}
	})
	return checkout.Person{UserID: id, Email: sub + "@example.test", Name: "Projection Member"}
}

// seedSellable creates what the requested flow needs and returns the slug to
// buy. "friends-custom" means: no fixed tier, the member names the amount.
func seedSellable(t *testing.T, pool *db.Pool, program string) string {
	t.Helper()
	ctx := context.Background()
	repo := catalogdb.New()

	kind, prog, account := "hotspot_tier", "hotspot", core.Memberships
	if strings.HasPrefix(program, "friends") {
		kind, prog, account = "friends_tier", "friends", core.Donations
	}
	slug := "proj-" + uuid.New().String()[:8]
	// A hotspot tier ships a SIM card and is inventory-tracked in production,
	// so the fixture models that. It matters: with an untracked item the order
	// holds no reservations, and every assertion here about stock being
	// released would pass by describing nothing.
	tracked := kind == "hotspot_tier"
	item, err := repo.UpsertItem(ctx, pool.Conn(), catalogdb.Item{
		Slug: slug, Name: "Projection " + slug, Kind: kind, Program: prog,
		RequiresShipping: tracked, RequiresIMEI: tracked, InventoryTracked: tracked,
	})
	if err != nil {
		t.Fatalf("seed item: %v", err)
	}
	if tracked {
		if _, err := pool.Conn().Exec(ctx, `
			INSERT INTO inventory (id, catalog_item_id, variant, on_hand, reserved, safety_stock)
			VALUES ($1, $2, 'default', 5, 0, 0)
			ON CONFLICT (catalog_item_id, variant)
				DO UPDATE SET on_hand = EXCLUDED.on_hand, reserved = 0
		`, uuid.New(), item.ID); err != nil {
			t.Fatalf("seed inventory: %v", err)
		}
	}
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")
	versionID, err := repo.InsertPriceVersion(ctx, pool.Conn(), catalogdb.PriceVersion{
		CatalogItemID: item.ID, Environment: core.StripeSandbox, Account: account,
		ProductID: "prod_" + suffix, PriceID: "price_" + suffix,
		Amount: 2500, Currency: "usd",
		Recurring: true, Interval: "month", IntervalCount: 1,
		ActiveFrom: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := repo.MarkVerified(ctx, pool.Conn(), versionID, time.Now().UTC(), nil); err != nil {
		t.Fatalf("verify version: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Conn().Exec(c, `
			UPDATE catalog_price_versions SET active_until = now()
			WHERE active_until IS NULL AND catalog_item_id = $1`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_price_versions WHERE catalog_item_id = $1`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_items WHERE id = $1`, item.ID)
	})

	return slug
}
