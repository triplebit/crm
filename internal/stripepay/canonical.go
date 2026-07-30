package stripepay

import (
	"context"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// CanonicalSession is the Checkout Session as Stripe holds it now — not as an
// event described it.
//
// The distinction is the whole point of retrieving. A webhook payload is a
// snapshot of one moment, and events can arrive late, out of order, or
// duplicated; the object Stripe returns when asked is the current truth. So
// nothing in this portal projects from a payload: an event says which object
// changed, and then the object is fetched and that is what gets written.
type CanonicalSession struct {
	ID             string
	PaymentStatus  string
	Status         string
	Mode           string
	AmountTotal    int64
	Currency       string
	CustomerID     string
	OrderReference string

	PaymentIntentID string
	SubscriptionID  string
	InvoiceID       string

	// ShippingName and ShippingAddress are what the member typed on Stripe's
	// hosted page. They are read here and handed to staff on demand; per D9
	// the portal stores neither.
	//
	// `json:"-"` is what makes that true rather than merely stated. The comment
	// above said the same thing while the projector marshalled this whole struct
	// into stripe_projection_applications.canonical — whose own column comment
	// also forbids address detail — writing plaintext addresses into the one
	// table the worker can reach without a PII key. Three assertions of a
	// property and no mechanism enforcing it.
	//
	// The tag is deliberately here rather than in a separate minimized audit
	// struct: a DTO leaves this type marshalable, so the next caller to reach
	// for json.Marshal reintroduces the leak. Unserializable at the source
	// cannot be bypassed by accident. TestCanonicalSessionNeverSerializesAnAddress
	// holds the line.
	ShippingName    string `json:"-"`
	ShippingAddress string `json:"-"`

	// RetrievedAt is the instant this was read, and the ordering key for the
	// out-of-order guard. See migration 000004: event.created would reject
	// exactly the late-delivered event that carries the freshest state.
	RetrievedAt time.Time
}

// GetCanonicalSession retrieves a Checkout Session with the objects the
// projector needs expanded, so one round trip yields the whole settlement
// picture rather than four.
func (c *Client) GetCanonicalSession(ctx context.Context, account core.AccountRef, sessionID string) (CanonicalSession, error) {
	base, err := c.readParams(account)
	if err != nil {
		return CanonicalSession{}, err
	}
	params := &stripe.CheckoutSessionRetrieveParams{Params: base}
	params.AddExpand("payment_intent")
	params.AddExpand("subscription")
	params.AddExpand("invoice")

	got, err := c.sc.V1CheckoutSessions.Retrieve(ctx, sessionID, params)
	if err != nil {
		return CanonicalSession{}, fmt.Errorf("stripepay: retrieve session %s: %w", sessionID, err)
	}

	out := CanonicalSession{
		ID:             got.ID,
		PaymentStatus:  string(got.PaymentStatus),
		Status:         string(got.Status),
		Mode:           string(got.Mode),
		AmountTotal:    got.AmountTotal,
		Currency:       string(got.Currency),
		OrderReference: got.ClientReferenceID,
		RetrievedAt:    c.now().UTC(),
	}
	if got.Customer != nil {
		out.CustomerID = got.Customer.ID
	}
	if got.PaymentIntent != nil {
		out.PaymentIntentID = got.PaymentIntent.ID
	}
	if got.Subscription != nil {
		out.SubscriptionID = got.Subscription.ID
	}
	if got.Invoice != nil {
		out.InvoiceID = got.Invoice.ID
	}
	if info := got.CollectedInformation; info != nil && info.ShippingDetails != nil {
		out.ShippingName = info.ShippingDetails.Name
		out.ShippingAddress = formatAddress(info.ShippingDetails.Address)
	}
	return out, nil
}

// CanonicalSubscription is a subscription as Stripe holds it now.
type CanonicalSubscription struct {
	ID                string
	Status            string
	CustomerID        string
	PriceID           string
	CancelAtPeriodEnd bool
	CurrentPeriodEnd  time.Time
	RetrievedAt       time.Time
}

// GetCanonicalSubscription retrieves a subscription.
func (c *Client) GetCanonicalSubscription(ctx context.Context, account core.AccountRef, subscriptionID string) (CanonicalSubscription, error) {
	base, err := c.readParams(account)
	if err != nil {
		return CanonicalSubscription{}, err
	}
	got, err := c.sc.V1Subscriptions.Retrieve(ctx, subscriptionID,
		&stripe.SubscriptionRetrieveParams{Params: base})
	if err != nil {
		return CanonicalSubscription{}, fmt.Errorf("stripepay: retrieve subscription %s: %w", subscriptionID, err)
	}

	out := CanonicalSubscription{
		ID:                got.ID,
		Status:            string(got.Status),
		CancelAtPeriodEnd: got.CancelAtPeriodEnd,
		RetrievedAt:       c.now().UTC(),
	}
	if got.Customer != nil {
		out.CustomerID = got.Customer.ID
	}
	// One price per subscription is this portal's rule, not Stripe's: a
	// membership is one tier. Taking the first item is therefore reading what
	// we wrote, and a second item would mean something else created it.
	if len(got.Items.Data) > 0 {
		item := got.Items.Data[0]
		if item.Price != nil {
			out.PriceID = item.Price.ID
		}
		if item.CurrentPeriodEnd != 0 {
			out.CurrentPeriodEnd = time.Unix(item.CurrentPeriodEnd, 0).UTC()
		}
	}
	return out, nil
}

// formatAddress renders a Stripe address as a single human-readable block,
// for staff to read off a screen. It is never stored (D9).
func formatAddress(a *stripe.Address) string {
	if a == nil {
		return ""
	}
	parts := []string{a.Line1, a.Line2, a.City, a.State, a.PostalCode, a.Country}
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += "\n"
		}
		out += p
	}
	return out
}
