package stripepay

import (
	"context"
	"errors"
	"fmt"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// CustomerSpec describes a Customer to create. Email and name come from
// Pocket ID; LocalAccountID is the portal's user identifier, recorded as
// metadata so a Customer in the Dashboard can always be traced to a row.
type CustomerSpec struct {
	Email          string
	Name           string
	LocalAccountID string
}

// Customer is the subset of a Stripe Customer the portal reads.
type Customer struct {
	ID    string
	Email string
	Name  string
}

// CreateCustomer creates a Customer in the given account. With Organization
// customer sharing enabled, the same cus_ identifier becomes visible in the
// sibling account within seconds; callers handle that propagation window via
// GetCustomer and IsNotFound.
func (c *Client) CreateCustomer(ctx context.Context, account core.AccountRef, idempotencyKey string, spec CustomerSpec) (Customer, error) {
	if spec.LocalAccountID == "" {
		return Customer{}, errors.New("stripepay: a customer needs the local account id it belongs to")
	}
	base, err := c.mutationParams(account, idempotencyKey)
	if err != nil {
		return Customer{}, err
	}
	params := &stripe.CustomerCreateParams{
		Params:   base,
		Metadata: map[string]string{"portal_account_id": spec.LocalAccountID},
	}
	if spec.Email != "" {
		params.Email = stripe.String(spec.Email)
	}
	if spec.Name != "" {
		params.Name = stripe.String(spec.Name)
	}
	created, err := c.sc.V1Customers.Create(ctx, params)
	if err != nil {
		return Customer{}, fmt.Errorf("stripepay: create customer: %w", err)
	}
	return toCustomer(created), nil
}

// GetCustomer reads a Customer back from one account.
func (c *Client) GetCustomer(ctx context.Context, account core.AccountRef, customerID string) (Customer, error) {
	base, err := c.readParams(account)
	if err != nil {
		return Customer{}, err
	}
	got, err := c.sc.V1Customers.Retrieve(ctx, customerID, &stripe.CustomerRetrieveParams{Params: base})
	if err != nil {
		return Customer{}, fmt.Errorf("stripepay: retrieve customer %s: %w", customerID, err)
	}
	return toCustomer(got), nil
}

// IsNotFound reports whether err is Stripe saying the object does not exist
// in the addressed account — which, for a freshly shared Customer, means
// "not yet": propagation to the sibling account takes seconds, and callers
// retry with a bound instead of failing.
func IsNotFound(err error) bool {
	var stripeErr *stripe.Error
	return errors.As(err, &stripeErr) && stripeErr.Code == stripe.ErrorCodeResourceMissing
}

func toCustomer(c *stripe.Customer) Customer {
	return Customer{ID: c.ID, Email: c.Email, Name: c.Name}
}
