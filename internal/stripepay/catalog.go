package stripepay

import (
	"context"
	"errors"
	"fmt"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// The catalog operations. Only what catalog-sync needs: create a product,
// keep its name current, create a price, retire a price, and read both back
// for verification. No stripe-go type crosses this boundary — callers see
// these structs, so a library major bump stays inside this package.

// ProductSpec describes a product to create.
type ProductSpec struct {
	// Name is what Stripe shows on invoices and in Checkout.
	Name string
	// Slug is the catalog item's slug, recorded as metadata so a human in
	// the Stripe Dashboard can trace any product back to the manifest line
	// that created it.
	Slug string
}

// Product is the subset of a Stripe Product the portal reads.
type Product struct {
	ID     string
	Name   string
	Active bool
}

// PriceSpec describes a price to create. Amounts are integer minor units
// (cents); there is no float anywhere in this path.
type PriceSpec struct {
	ProductID  string
	Slug       string
	UnitAmount int64
	Currency   string
	// Recurring prices bill on an interval; one-time prices leave Interval
	// empty and IntervalCount zero.
	Recurring     bool
	Interval      string
	IntervalCount int64
}

// Price is the subset of a Stripe Price the portal reads.
type Price struct {
	ID            string
	ProductID     string
	UnitAmount    int64
	Currency      string
	Active        bool
	LookupKey     string
	Recurring     bool
	Interval      string
	IntervalCount int64
}

// CreateProduct creates a product in the given account.
func (c *Client) CreateProduct(ctx context.Context, account core.AccountRef, idempotencyKey string, spec ProductSpec) (Product, error) {
	if spec.Name == "" || spec.Slug == "" {
		return Product{}, errors.New("stripepay: a product needs a name and a slug")
	}
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Product{}, err
	}
	created, err := c.sc.V1Products.Create(ctx, &stripe.ProductCreateParams{
		Params:   base,
		Name:     stripe.String(spec.Name),
		Metadata: map[string]string{"portal_slug": spec.Slug},
	})
	if err != nil {
		return Product{}, fmt.Errorf("stripepay: create product for %q: %w", spec.Slug, err)
	}
	return toProduct(created), nil
}

// UpdateProductName renames a product; prices are immutable in Stripe but
// display names are not, and the manifest owns them.
func (c *Client) UpdateProductName(ctx context.Context, account core.AccountRef, idempotencyKey, productID, name string) (Product, error) {
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Product{}, err
	}
	updated, err := c.sc.V1Products.Update(ctx, productID, &stripe.ProductUpdateParams{
		Params: base,
		Name:   stripe.String(name),
	})
	if err != nil {
		return Product{}, fmt.Errorf("stripepay: rename product %s: %w", productID, err)
	}
	return toProduct(updated), nil
}

// GetProduct reads a product back.
func (c *Client) GetProduct(ctx context.Context, account core.AccountRef, productID string) (Product, error) {
	base, err := c.readParams(account)
	if err != nil {
		return Product{}, err
	}
	got, err := c.sc.V1Products.Retrieve(ctx, productID, &stripe.ProductRetrieveParams{Params: base})
	if err != nil {
		return Product{}, fmt.Errorf("stripepay: retrieve product %s: %w", productID, err)
	}
	return toProduct(got), nil
}

// CreatePrice creates a price under an existing product. Stripe prices are
// immutable once created, which is exactly why the catalog stores versions:
// a price change is a new price plus a retirement, never an edit.
func (c *Client) CreatePrice(ctx context.Context, account core.AccountRef, idempotencyKey string, spec PriceSpec) (Price, error) {
	switch {
	case spec.ProductID == "":
		return Price{}, errors.New("stripepay: a price needs a product")
	case spec.Currency == "":
		return Price{}, errors.New("stripepay: a price needs a currency")
	case spec.UnitAmount < 0:
		return Price{}, errors.New("stripepay: a price cannot be negative")
	case spec.Recurring && spec.Interval == "":
		return Price{}, errors.New("stripepay: a recurring price needs an interval")
	case !spec.Recurring && (spec.Interval != "" || spec.IntervalCount != 0):
		return Price{}, errors.New("stripepay: a one-time price must not carry an interval")
	}
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Price{}, err
	}
	params := &stripe.PriceCreateParams{
		Params:     base,
		Product:    stripe.String(spec.ProductID),
		Currency:   stripe.String(spec.Currency),
		UnitAmount: stripe.Int64(spec.UnitAmount),
		Metadata:   map[string]string{"portal_slug": spec.Slug},
	}
	if spec.Recurring {
		count := spec.IntervalCount
		if count == 0 {
			count = 1
		}
		params.Recurring = &stripe.PriceCreateRecurringParams{
			Interval:      stripe.String(spec.Interval),
			IntervalCount: stripe.Int64(count),
		}
	}
	created, err := c.sc.V1Prices.Create(ctx, params)
	if err != nil {
		return Price{}, fmt.Errorf("stripepay: create price for %q: %w", spec.Slug, err)
	}
	return toPrice(created), nil
}

// DeactivatePrice retires a price so nothing new can be sold at it. Existing
// subscriptions keep billing at their agreed amount; that is Stripe's
// behaviour and the desired one.
func (c *Client) DeactivatePrice(ctx context.Context, account core.AccountRef, idempotencyKey, priceID string) (Price, error) {
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Price{}, err
	}
	updated, err := c.sc.V1Prices.Update(ctx, priceID, &stripe.PriceUpdateParams{
		Params: base,
		Active: stripe.Bool(false),
	})
	if err != nil {
		return Price{}, fmt.Errorf("stripepay: deactivate price %s: %w", priceID, err)
	}
	return toPrice(updated), nil
}

// GetPrice reads a price back; catalog-sync uses it to verify that what the
// database records is what Stripe holds before marking a version verified.
func (c *Client) GetPrice(ctx context.Context, account core.AccountRef, priceID string) (Price, error) {
	base, err := c.readParams(account)
	if err != nil {
		return Price{}, err
	}
	got, err := c.sc.V1Prices.Retrieve(ctx, priceID, &stripe.PriceRetrieveParams{Params: base})
	if err != nil {
		return Price{}, fmt.Errorf("stripepay: retrieve price %s: %w", priceID, err)
	}
	return toPrice(got), nil
}

func toProduct(p *stripe.Product) Product {
	return Product{ID: p.ID, Name: p.Name, Active: p.Active}
}

func toPrice(p *stripe.Price) Price {
	out := Price{
		ID:         p.ID,
		UnitAmount: p.UnitAmount,
		Currency:   string(p.Currency),
		Active:     p.Active,
		LookupKey:  p.LookupKey,
	}
	if p.Product != nil {
		out.ProductID = p.Product.ID
	}
	if p.Recurring != nil {
		out.Recurring = true
		out.Interval = string(p.Recurring.Interval)
		out.IntervalCount = p.Recurring.IntervalCount
	}
	return out
}
