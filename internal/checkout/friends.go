package checkout

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/money"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/stripepay"
)

// Custom giving amounts are bounded. The floor keeps card fees from eating
// the whole gift; the ceiling is a typo guard — a member who genuinely wants
// to give more monthly than this should talk to a human, who can also thank
// them properly.
const (
	minCustomDonation  = money.Cents(100)     // $1.00
	maxCustomDonation  = money.Cents(200_000) // $2,000.00
	customDonationSlug = "friends-custom"
	customDonationName = "Friends of Triplebit — monthly"
)

// FriendsRequest is a member's Friends choice: either one of the catalog's
// fixed monthly tiers, or an amount they chose themselves.
type FriendsRequest struct {
	// TierSlug selects a fixed tier. Empty means a custom amount.
	TierSlug string

	// CustomAmount is a dollar string as typed ("12", "12.50"). It is parsed
	// to exact cents by internal/money — no float is ever constructed — and
	// bounded before it can reach Stripe.
	CustomAmount string
}

// StartFriends turns a Friends choice into a Stripe Checkout URL.
//
// It shares the enrolment machinery — resume-or-replay, frozen lines, the
// same crash window — and differs in exactly two ways: nothing ships, so no
// address is collected and no inventory is held; and the amount may be the
// member's own choice rather than a catalog price.
//
// That second difference is the one place in this codebase where an amount
// legitimately arrives from a browser. It is not a price being trusted: a
// price says what a thing costs and must come from the catalog, whereas this
// says what a person decided to give. The server still parses it to exact
// cents itself and bounds it; what it cannot do is disagree with the member
// about their own generosity.
func (s *Service) StartFriends(ctx context.Context, person Person, req FriendsRequest) (string, error) {
	// Validate before resuming, so a bad amount is answered as a bad amount
	// rather than with a pending checkout page and no explanation.
	line := orders.Line{
		ID:         uuid.New(),
		LineNumber: 1,
		Kind:       "friends_tier",
		Quantity:   1,
		Account:    core.Donations,
	}

	if slug := strings.TrimSpace(req.TierSlug); slug != "" {
		item, version, err := s.sellable(ctx, slug, "friends_tier")
		if err != nil {
			return "", err
		}
		line.CatalogItemID = item.ID
		line.CatalogPriceVersionID = version.ID
		line.Slug = item.Slug
		line.Name = item.Name
		line.StripeProductID = version.ProductID
		line.StripePriceID = version.PriceID
		line.Amount = version.Amount
		line.Currency = version.Currency
	} else {
		amount, err := money.ParseDollars(req.CustomAmount)
		if err != nil {
			return "", safeerr.WithStatus(http.StatusUnprocessableEntity,
				"Enter an amount in dollars, like 12 or 12.50.")
		}
		if amount < minCustomDonation || amount > maxCustomDonation {
			return "", safeerr.WithStatus(http.StatusUnprocessableEntity,
				"Choose a monthly amount between "+minCustomDonation.Display()+
					" and "+maxCustomDonation.Display()+", or contact us to give more.")
		}
		// No catalog item and no price version: the member set the price, so
		// there is no version to point at. The line's own amount is the
		// frozen record, which is what an order line is for.
		line.Slug = customDonationSlug
		line.Name = customDonationName
		line.Amount = int64(amount)
		line.Currency = "usd"
	}

	if url, ok, err := s.resumePending(ctx, person, "friends"); err != nil || ok {
		return url, err
	}

	customerID, err := s.EnsureCustomer(ctx, core.Donations, person)
	if err != nil {
		return "", err
	}

	orderID := uuid.New()
	order := orders.Order{
		ID:             orderID,
		UserID:         person.UserID,
		Program:        "friends",
		Environment:    s.env,
		Account:        core.Donations,
		Currency:       line.Currency,
		IdempotencyKey: "order:" + orderID.String(),
	}
	if err := s.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		return s.orders.CreatePending(ctx, c, order, []orders.Line{line})
	}); err != nil {
		if url, ok, resumeErr := s.resumeAfterRace(ctx, person, "friends", err); ok || resumeErr != nil {
			return url, resumeErr
		}
		return "", err
	}

	return s.createAndAttachSessionFor(ctx, order, []orders.Line{line}, customerID, true)
}

// FriendsChoice is one fixed monthly tier, priced.
type FriendsChoice struct {
	Slug     string
	Name     string
	Amount   int64
	Currency string
	Interval string
}

// FriendsOffer is what the giving page shows.
type FriendsOffer struct {
	Tiers     []FriendsChoice
	MinCustom money.Cents
	MaxCustom money.Cents
}

// FriendsOffer lists the current fixed tiers plus the custom-amount bounds.
func (s *Service) FriendsOffer(ctx context.Context) (FriendsOffer, error) {
	tiers, err := s.catalog.SellableByKind(ctx, s.pool.Conn(), s.env, core.Donations, "friends_tier")
	if err != nil {
		return FriendsOffer{}, err
	}
	offer := FriendsOffer{MinCustom: minCustomDonation, MaxCustom: maxCustomDonation}
	for _, t := range tiers {
		offer.Tiers = append(offer.Tiers, FriendsChoice{
			Slug:     t.Item.Slug,
			Name:     t.Item.Name,
			Amount:   t.Version.Amount,
			Currency: t.Version.Currency,
			Interval: t.Version.Interval,
		})
	}
	return offer, nil
}

// donationFor rebuilds the inline-price shape for a stored custom-amount
// line: a line with an amount but no Stripe price id can only have been a
// member-chosen donation.
func donationFor(line orders.Line) *stripepay.DonationLine {
	if line.StripePriceID != "" {
		return nil
	}
	interval := ""
	if line.Kind == "friends_tier" {
		interval = "month"
	}
	name := line.Name
	if name == "" {
		name = customDonationName
	}
	return &stripepay.DonationLine{
		ProductName:   name,
		Amount:        line.Amount,
		Currency:      line.Currency,
		Interval:      interval,
		IntervalCount: 1,
	}
}
