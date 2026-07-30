package stripepay

import (
	"context"
	"errors"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// SessionLine is one Checkout line item, referencing a catalog price by its
// Stripe identifier. There is deliberately no ad-hoc amount variant for
// catalog goods — the server resolves prices from the verified catalog, and
// an amount that can be passed here is an amount that can be tampered with
// upstream. (Custom-amount donations get their own explicit path when the
// donate flow lands.)
type SessionLine struct {
	PriceID  string
	Quantity int64
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

	// ExpiresAt bounds how long the hosted page can complete. Stripe
	// requires 30 minutes to 24 hours.
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
		if line.PriceID == "" || line.Quantity <= 0 {
			return Session{}, errors.New("stripepay: a checkout line needs a price and a positive quantity")
		}
		params.LineItems = append(params.LineItems, &stripe.CheckoutSessionCreateLineItemParams{
			Price:    stripe.String(line.PriceID),
			Quantity: stripe.Int64(line.Quantity),
		})
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
