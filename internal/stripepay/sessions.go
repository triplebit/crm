package stripepay

import (
	"context"
	"errors"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// SessionLine is one Checkout line item. Normally it references a catalog
// price by its Stripe identifier: the server resolves prices from the
// verified catalog, so no amount for a good crosses this boundary and none
// can be tampered with upstream.
//
// Donation is the one exception, and it is a different kind of thing. A
// member choosing what to give is not a price the catalog can know — the
// amount IS their decision. Such a line carries no PriceID and instead names
// its own amount, which the service has already parsed to exact cents and
// bounded. The field is named Donation, not Amount, so a future caller
// cannot reach for it while selling a device.
type SessionLine struct {
	PriceID  string
	Quantity int64

	Donation *DonationLine
}

// DonationLine is a member-chosen giving amount, rendered as an inline
// Stripe price. Recurring when Interval is set.
type DonationLine struct {
	// ProductName is what the member sees on the hosted page and the
	// receipt.
	ProductName string
	Amount      int64
	Currency    string

	Interval      string
	IntervalCount int64
}

// SessionSpec describes a Checkout Session to create.
type SessionSpec struct {
	CustomerID string
	Lines      []SessionLine

	// Subscription mode when the order carries a recurring tier; payment
	// mode for one-time-only carts.
	Subscription bool

	// ClientReferenceID carries the portal's order id, so every webhook and
	// Dashboard view traces back to a local row.
	ClientReferenceID string

	SuccessURL string
	CancelURL  string

	// ExpiresAt bounds how long the hosted page can complete (Stripe allows
	// 30 minutes to 24 hours; the default is 24 hours).
	//
	// Callers that rely on idempotent replay must leave this zero: a value
	// derived from the current time makes each attempt's parameters differ,
	// and Stripe refuses a replayed key whose parameters changed.
	ExpiresAt time.Time

	// CollectShipping asks Stripe to collect a shipping address on the
	// hosted page. Stripe validates and autocompletes it, and the address
	// arrives back on the settled session — so the portal never stores one
	// for an order that was never paid.
	CollectShipping bool
}

// shippingCountries is where the portal ships. Hotspot service is US mobile
// service, so this is the US; widening it is one line and a policy decision,
// not a code change.
var shippingCountries = []string{"US"}

// Session is the subset of a Checkout Session the portal reads at creation.
type Session struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

// CreateCheckoutSession creates a hosted Checkout page.
//
// payment_method_types is pinned to card here, inside the only package that
// can talk to Stripe, so card-only is a property of the code rather than a
// Dashboard setting someone can flip. Enabling ACH in the Dashboard would
// otherwise silently make four deferred webhook event types load-bearing.
func (c *Client) CreateCheckoutSession(ctx context.Context, account core.AccountRef, idempotencyKey string, spec SessionSpec) (Session, error) {
	switch {
	case spec.CustomerID == "":
		return Session{}, errors.New("stripepay: a checkout session needs a customer")
	case len(spec.Lines) == 0:
		return Session{}, errors.New("stripepay: a checkout session needs at least one line")
	case spec.ClientReferenceID == "":
		return Session{}, errors.New("stripepay: a checkout session needs the order reference")
	case spec.SuccessURL == "" || spec.CancelURL == "":
		return Session{}, errors.New("stripepay: a checkout session needs success and cancel URLs")
	}
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Session{}, err
	}

	mode := "payment"
	if spec.Subscription {
		mode = "subscription"
	}
	params := &stripe.CheckoutSessionCreateParams{
		Params:             base,
		Mode:               stripe.String(mode),
		Customer:           stripe.String(spec.CustomerID),
		ClientReferenceID:  stripe.String(spec.ClientReferenceID),
		SuccessURL:         stripe.String(spec.SuccessURL),
		CancelURL:          stripe.String(spec.CancelURL),
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
	}
	if !spec.ExpiresAt.IsZero() {
		params.ExpiresAt = stripe.Int64(spec.ExpiresAt.Unix())
	}
	if spec.CollectShipping {
		params.ShippingAddressCollection = &stripe.CheckoutSessionCreateShippingAddressCollectionParams{
			AllowedCountries: stripe.StringSlice(shippingCountries),
		}
	}
	for _, line := range spec.Lines {
		if line.Quantity <= 0 {
			return Session{}, errors.New("stripepay: a checkout line needs a positive quantity")
		}
		item := &stripe.CheckoutSessionCreateLineItemParams{Quantity: stripe.Int64(line.Quantity)}
		switch {
		case line.Donation != nil && line.PriceID != "":
			return Session{}, errors.New("stripepay: a line is either a catalog price or a donation, never both")

		case line.Donation != nil:
			d := line.Donation
			if d.Amount <= 0 || d.Currency == "" || d.ProductName == "" {
				return Session{}, errors.New("stripepay: a donation line needs a positive amount, a currency and a name")
			}
			// product_data rather than a pre-made Product: the amount is the
			// member's, so there is no catalog price version to anchor it to.
			// Stripe therefore accumulates one Product per custom donation —
			// untidy in the Dashboard but harmless, and the upgrade (a single
			// anchor Product synced from the manifest) is a later, additive
			// change that needs no schema.
			item.PriceData = &stripe.CheckoutSessionCreateLineItemPriceDataParams{
				Currency:    stripe.String(d.Currency),
				UnitAmount:  stripe.Int64(d.Amount),
				ProductData: &stripe.CheckoutSessionCreateLineItemPriceDataProductDataParams{Name: stripe.String(d.ProductName)},
			}
			if d.Interval != "" {
				count := d.IntervalCount
				if count == 0 {
					count = 1
				}
				item.PriceData.Recurring = &stripe.CheckoutSessionCreateLineItemPriceDataRecurringParams{
					Interval:      stripe.String(d.Interval),
					IntervalCount: stripe.Int64(count),
				}
			}

		case line.PriceID != "":
			item.Price = stripe.String(line.PriceID)

		default:
			return Session{}, errors.New("stripepay: a checkout line needs a catalog price or a donation")
		}
		params.LineItems = append(params.LineItems, item)
	}

	created, err := c.sc.V1CheckoutSessions.Create(ctx, params)
	if err != nil {
		return Session{}, fmt.Errorf("stripepay: create checkout session: %w", err)
	}
	return Session{
		ID:        created.ID,
		URL:       created.URL,
		ExpiresAt: time.Unix(created.ExpiresAt, 0).UTC(),
	}, nil
}

// ExpireCheckoutSession makes a Checkout Session unpayable immediately.
//
// This is what lets the portal release inventory safely. Abandoning an order
// while its hosted page stays payable — Stripe's default window is 24 hours —
// would let a member pay for stock that had already been given to someone
// else. Expiring first closes that window.
//
// It also fails usefully: Stripe refuses to expire a session that has already
// completed, so an error here is the signal that the money arrived and the
// order must NOT be abandoned. Fail-safe by construction rather than by a
// check the caller has to remember.
func (c *Client) ExpireCheckoutSession(ctx context.Context, account core.AccountRef, idempotencyKey, sessionID string) error {
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return err
	}
	if _, err := c.sc.V1CheckoutSessions.Expire(ctx, sessionID,
		&stripe.CheckoutSessionExpireParams{Params: base}); err != nil {
		return fmt.Errorf("stripepay: expire session %s: %w", sessionID, err)
	}
	return nil
}
