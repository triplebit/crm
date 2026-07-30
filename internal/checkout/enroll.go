package checkout

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/stripepay"
)

// The hosted Checkout page's lifetime is deliberately left to Stripe's
// default (24 hours) rather than pinned by this service.
//
// That is not laziness, it is the fix for a real bug: a session's create
// parameters must be byte-identical across attempts, because the order's
// idempotency key is what makes the crash window recoverable. An expires_at
// computed from "now" differs on every attempt, so Stripe rejected the
// replay with idempotency_error — a failure the resume test missed only
// because both of its attempts happened to land inside the same second. The
// clock is now absent from the parameters entirely, so a resume is exact
// however much later it arrives.
//
// The inventory hold spans that same window plus a margin, so stock is never
// released while a member could still be paying for it.
const (
	sessionLifetime  = 24 * time.Hour
	reservationGrace = 1 * time.Hour

	// resumeWindow is how long a pending order may be resumed. It is shorter
	// than the hold (sessionLifetime + reservationGrace) so a resumed page can
	// never outlive the stock behind it, and shorter than Stripe's ~24-hour
	// idempotency retention so a resume replays rather than re-creates.
	resumeWindow = 20 * time.Hour
)

var imeiPattern = regexp.MustCompile(`^[0-9]{14,16}$`)

// EnrollmentRequest is a member's hotspot enrolment choice. Every field
// arrives from a browser form and is validated here; prices deliberately
// cannot arrive at all.
type EnrollmentRequest struct {
	TierSlug      string
	IncludeDevice bool

	// IMEI identifies the member's own device, and is required only when
	// they are bringing one: a device bought here has its IMEI recorded by
	// staff at fulfillment, from the unit actually shipped, which is the
	// only party who can know it. Asking the member for it would be asking
	// them to invent it.
	IMEI string
}

// The shipping address is absent from this struct, and from the database.
//
// Stripe collects it on the hosted page and keeps it on the settled session
// indefinitely, which makes Stripe the system of record. The portal therefore
// stores no home addresses at all: staff read the address from Stripe at the
// moment they print a label (M7), and there is nothing here to encrypt,
// rotate, sweep, leak, or hand to the worker. That last point resolves a real
// tension — the worker is deliberately denied the PII key (D7), so a design
// where it projected addresses would have forced either weakening that
// boundary or building an encrypt-only mechanism. Not storing the address is
// smaller than both and strictly more private.
//
// orders.shipping_address_ciphertext is consequently never written; M8 can
// drop the column.

// StartEnrollment turns a choice into a Stripe Checkout URL, crash-safe at
// every step:
//
//  1. Resolve and validate everything against the local, verified catalog.
//  2. One transaction: order (checkout_pending, no session yet), frozen
//     lines, inventory holds. The schema's reserved <= on_hand check makes
//     overselling roll the whole transaction back.
//  3. Create the Session with the order's idempotency key.
//  4. Attach the session id to the order.
//
// A crash between 2 and 4 leaves a pending order with no session — the
// member's next attempt finds it and replays step 3 on the same key, which
// returns the same Session. Nothing is charged by any of this; charging is
// M6's webhook business.
func (s *Service) StartEnrollment(ctx context.Context, person Person, req EnrollmentRequest) (string, error) {
	// Validate before resuming. A member whose input is wrong must be told
	// so, even if they happen to have a pending order — resuming first would
	// answer a typo with someone's forgotten checkout page and explain
	// nothing.
	tier, tierVersion, err := s.sellable(ctx, req.TierSlug, "hotspot_tier")
	if err != nil {
		return "", err
	}
	lines := []pendingLine{{item: tier, version: tierVersion, quantity: 1}}
	if req.IncludeDevice {
		device, deviceVersion, err := s.sellable(ctx, "hotspot-device", "device")
		if err != nil {
			return "", err
		}
		lines = append(lines, pendingLine{item: device, version: deviceVersion, quantity: 1})
	}

	if strings.TrimSpace(req.IMEI) != "" && req.IncludeDevice {
		// A device order carrying an IMEI means the form and the service
		// disagree about who supplies it. Refuse rather than store a number
		// staff will contradict at fulfillment.
		return "", safeerr.WithStatus(http.StatusUnprocessableEntity,
			"Leave the IMEI blank when we are sending you a device: we record it when it ships.")
	}
	if !req.IncludeDevice && !imeiPattern.MatchString(strings.ReplaceAll(strings.TrimSpace(req.IMEI), " ", "")) {
		return "", safeerr.WithStatus(http.StatusUnprocessableEntity,
			"Enter your device's IMEI: 14 to 16 digits, usually under Settings → About.")
	}

	// Only now: the schema allows one pending membership order per person, so
	// a double-click or a crashed attempt returns the same Checkout page.
	if url, ok, err := s.resumePending(ctx, person, "hotspot"); err != nil || ok {
		return url, err
	}

	orderID := uuid.New()
	imeiSealed := ""
	if !req.IncludeDevice {
		imei := strings.ReplaceAll(strings.TrimSpace(req.IMEI), " ", "")
		imeiSealed, err = s.pii.Encrypt(orderID.String(), "imei", []byte(imei))
		if err != nil {
			return "", fmt.Errorf("checkout: seal imei: %w", err)
		}
	}

	customerID, err := s.EnsureCustomer(ctx, core.Memberships, person)
	if err != nil {
		return "", err
	}

	order := orders.Order{
		ID:             orderID,
		UserID:         person.UserID,
		Program:        "hotspot",
		Environment:    s.env,
		Account:        core.Memberships,
		Currency:       tierVersion.Currency,
		IMEICiphertext: imeiSealed,
		IdempotencyKey: "order:" + orderID.String(),
	}

	now := s.now().UTC()
	err = s.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		var rows []orders.Line
		for i, pending := range lines {
			rows = append(rows, orders.Line{
				ID:                    uuid.New(),
				LineNumber:            i + 1,
				CatalogItemID:         pending.item.ID,
				CatalogPriceVersionID: pending.version.ID,
				Kind:                  pending.item.Kind,
				Slug:                  pending.item.Slug,
				Name:                  pending.item.Name,
				StripeProductID:       pending.version.ProductID,
				StripePriceID:         pending.version.PriceID,
				Amount:                pending.version.Amount,
				Currency:              pending.version.Currency,
				Quantity:              pending.quantity,
				RequiresShipping:      pending.item.RequiresShipping,
				InventoryTracked:      pending.item.InventoryTracked,
				Account:               core.Memberships,
			})
		}
		if err := s.orders.CreatePending(ctx, c, order, rows); err != nil {
			return err
		}
		for _, row := range rows {
			if !row.InventoryTracked {
				continue
			}
			if err := s.orders.Reserve(ctx, c, row.ID, row.CatalogItemID, row.Quantity,
				now.Add(sessionLifetime+reservationGrace)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// ErrInvalid is the reserved <= on_hand check refusing to oversell;
		// ErrNotFound is a tracked item with no inventory row at all. To the
		// member both mean the same thing.
		if errors.Is(err, db.ErrInvalid) || errors.Is(err, db.ErrNotFound) {
			return "", safeerr.WithStatus(http.StatusConflict,
				"That item is out of stock right now. Please try again later.")
		}
		// Two submissions raced past the pending-order check and this one lost
		// the unique index. The winner's order is the answer — which is what a
		// double-click should get, rather than a 500.
		if url, ok, resumeErr := s.resumeAfterRace(ctx, person, "hotspot", err); ok || resumeErr != nil {
			return url, resumeErr
		}
		return "", err
	}

	return s.createAndAttachSession(ctx, order, customerID, lines[0].version.Recurring)
}

// resumePending returns the Checkout URL for an existing pending order,
// replaying the Session create when the crash window left none attached.
func (s *Service) resumePending(ctx context.Context, person Person, program string) (string, bool, error) {
	pending, err := s.orders.PendingForUser(ctx, s.pool.Conn(), person.UserID, program, s.env)
	switch {
	case errors.Is(err, db.ErrNotFound):
		return "", false, nil
	case err != nil:
		return "", false, err
	}

	// A stale pending order must not be resurrected. Replaying its
	// idempotency key normally returns the original Session with its original
	// expiry — but Stripe prunes idempotency records after about a day, and a
	// replay past that mints a genuinely new, payable 24-hour Session while
	// this order's inventory hold is already expiring. Rather than chase the
	// hold forward, abandon the order: the member gets a fresh one at current
	// prices, and the stock goes back.
	if s.now().UTC().After(pending.CreatedAt.Add(resumeWindow)) {
		if err := s.abandon(ctx, pending); err != nil {
			return "", false, err
		}
		return "", false, nil
	}

	// A still-valid session: hand back its page. The URL is not stored (it
	// is derivable by re-creating on the same idempotency key), so replay.
	customerID, err := s.EnsureCustomer(ctx, pending.Account, person)
	if err != nil {
		return "", false, err
	}
	lines, err := s.orders.Lines(ctx, s.pool.Conn(), pending.ID)
	if err != nil {
		return "", false, err
	}
	recurring := false
	for _, line := range lines {
		if line.Kind == "hotspot_tier" || line.Kind == "friends_tier" {
			recurring = true
		}
	}
	url, err := s.createAndAttachSessionFor(ctx, pending, lines, customerID, recurring)
	if err != nil {
		return "", false, err
	}
	return url, true, nil
}

func (s *Service) createAndAttachSession(ctx context.Context, order orders.Order, customerID string, recurring bool) (string, error) {
	lines, err := s.orders.Lines(ctx, s.pool.Conn(), order.ID)
	if err != nil {
		return "", err
	}
	return s.createAndAttachSessionFor(ctx, order, lines, customerID, recurring)
}

func (s *Service) createAndAttachSessionFor(ctx context.Context, order orders.Order, lines []orders.Line, customerID string, recurring bool) (string, error) {
	spec := stripepay.SessionSpec{
		CustomerID:        customerID,
		Subscription:      recurring,
		ClientReferenceID: order.ID.String(),
		SuccessURL:        s.baseURL + "/account?checkout=done",
		CancelURL:         s.baseURL + "/account?checkout=canceled",
	}
	for _, line := range lines {
		// A line with no Stripe price id is a member-chosen donation: the
		// amount on the line is the whole record, and the inline price is
		// rebuilt from it — identically on a first attempt and on a resume.
		spec.Lines = append(spec.Lines, stripepay.SessionLine{
			PriceID:  line.StripePriceID,
			Quantity: int64(line.Quantity),
			Donation: donationFor(line),
		})
		// The frozen line already records whether it ships, so the hosted
		// page asks for an address exactly when something physical is being
		// sold — the catalog decides, not the handler.
		if line.RequiresShipping {
			spec.CollectShipping = true
		}
	}
	session, err := s.pay.CreateCheckoutSession(ctx, order.Account, order.IdempotencyKey, spec)
	if err != nil {
		return "", err
	}
	if err := s.orders.AttachSession(ctx, s.pool.Conn(), order.ID, session.ID, session.ExpiresAt); err != nil {
		return "", err
	}
	return session.URL, nil
}

// sellable resolves a slug into an active item with a verified current price
// of the expected kind, or a member-visible refusal.
func (s *Service) sellable(ctx context.Context, slug, kind string) (catalogdb.Item, catalogdb.PriceVersion, error) {
	item, err := s.catalog.ItemBySlug(ctx, s.pool.Conn(), slug)
	if errors.Is(err, db.ErrNotFound) {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, safeerr.WithStatus(http.StatusNotFound,
			"That option is not available.")
	}
	if err != nil {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, err
	}
	if !item.Active || item.Kind != kind {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, safeerr.WithStatus(http.StatusNotFound,
			"That option is not available.")
	}
	version, err := s.catalog.CurrentPriceVersion(ctx, s.pool.Conn(), item.ID, s.env, itemAccount(item))
	if errors.Is(err, db.ErrNotFound) {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, safeerr.WithStatus(http.StatusNotFound,
			"That option is not available.")
	}
	if err != nil {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, err
	}
	// An unverified version has never been proven against Stripe; selling at
	// it would trust a write that was never read back.
	if version.VerifiedAt == nil {
		return catalogdb.Item{}, catalogdb.PriceVersion{}, fmt.Errorf(
			"checkout: price version %s for %q is unverified", version.ID, slug)
	}
	return item, version, nil
}

// itemAccount mirrors the catalog manifest's program routing.
func itemAccount(item catalogdb.Item) core.AccountRef {
	if item.Program == "hotspot" {
		return core.Memberships
	}
	return core.Donations
}

// TierChoice is one enrolment option, priced.
type TierChoice struct {
	Slug          string
	Name          string
	Amount        int64
	Currency      string
	Interval      string
	IntervalCount int64
}

// EnrollmentOffer is what the enrolment page shows: the tiers, and whether a
// device can currently be added.
type EnrollmentOffer struct {
	Tiers []TierChoice

	DeviceAvailable bool
	DeviceAmount    int64
}

// Offer lists the current hotspot enrolment options from the verified
// catalog.
func (s *Service) Offer(ctx context.Context) (EnrollmentOffer, error) {
	tiers, err := s.catalog.SellableByKind(ctx, s.pool.Conn(), s.env, core.Memberships, "hotspot_tier")
	if err != nil {
		return EnrollmentOffer{}, err
	}
	offer := EnrollmentOffer{}
	for _, t := range tiers {
		offer.Tiers = append(offer.Tiers, TierChoice{
			Slug:          t.Item.Slug,
			Name:          t.Item.Name,
			Amount:        t.Version.Amount,
			Currency:      t.Version.Currency,
			Interval:      t.Version.Interval,
			IntervalCount: t.Version.IntervalCount,
		})
	}
	devices, err := s.catalog.SellableByKind(ctx, s.pool.Conn(), s.env, core.Memberships, "device")
	if err != nil {
		return EnrollmentOffer{}, err
	}
	for _, d := range devices {
		if d.Item.Slug == "hotspot-device" {
			offer.DeviceAvailable = true
			offer.DeviceAmount = d.Version.Amount
		}
	}
	return offer, nil
}

// resumeAfterRace turns a lost one-pending-order race into the winner's
// Checkout page. It insists on the named constraint: any other conflict is a
// different bug and must not be swallowed.
func (s *Service) resumeAfterRace(ctx context.Context, person Person, program string, cause error) (string, bool, error) {
	if db.ConstraintOf(cause) != "orders_one_pending_membership_program_per_user_idx" {
		return "", false, nil
	}
	url, ok, err := s.resumePending(ctx, person, program)
	if err != nil {
		return "", false, err
	}
	if !ok {
		// The winner vanished between the conflict and this read, so there is
		// nothing to resume and the original error is the honest answer.
		return "", false, nil
	}
	return url, true, nil
}

// abandon retires a stale pending order: unpayable first, then released.
//
// The order matters. Releasing stock while the hosted page is still payable —
// Stripe's window is 24 hours, longer than resumeWindow — would let a member
// pay for stock already given to someone else. And because Stripe refuses to
// expire a session that has completed, an error here means the money arrived,
// so nothing is released and the projector settles the order instead. The
// unsafe interleaving is unreachable rather than guarded against.
func (s *Service) abandon(ctx context.Context, order orders.Order) error {
	if order.CheckoutSessionID != "" {
		if err := s.pay.ExpireCheckoutSession(ctx, order.Account,
			"expire:"+order.CheckoutSessionID, order.CheckoutSessionID); err != nil {
			return err
		}
	}
	// One transaction: the four writes Abandon makes must all land or none,
	// or a retry finds the order already out of checkout_pending and never
	// repairs the rest.
	return s.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		_, err := s.orders.Abandon(ctx, c, order.ID, s.now().UTC(),
			"checkout not completed within the reservation window")
		return err
	})
}
