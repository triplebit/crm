package stripepay

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	stripe "github.com/stripe/stripe-go/v86"
	"github.com/stripe/stripe-go/v86/webhook"

	"triplebit.org/portal/internal/core"
)

// ErrBadSignature means the payload did not come from Stripe — wrong
// signature, or a timestamp outside the tolerance window (replay defence). It
// is deliberately one error: a caller has nothing to do differently, and
// telling a forger which half failed helps only them.
var ErrBadSignature = errors.New("stripepay: webhook signature is not valid")

// ErrAPIVersionMismatch means the event was authentic but its Stripe API
// version is not the one this build of stripe-go understands.
//
// It is a separate error because the two demand opposite responses. A bad
// signature might be an attack and should be investigated. A version mismatch
// is a misconfigured endpoint — the webhook was created against a different API
// version — and every event will fail identically until someone fixes it in the
// Stripe Dashboard. Reporting the second as the first sends an operator hunting
// an intruder instead of reading ExpectedAPIVersion.
var ErrAPIVersionMismatch = errors.New("stripepay: webhook event API version is not the expected one")

// ExpectedAPIVersion is the Stripe API version this build understands, and the
// version a webhook endpoint must be created with. `portal doctor` reports it
// so the value never has to be guessed from a library upgrade.
const ExpectedAPIVersion = stripe.APIVersion

// Event is the subset of a verified Stripe event the portal acts on. The
// stripe-go type is deliberately not exposed: nothing outside this package
// should be able to reach into a raw event and act on an unverified field.
type Event struct {
	ID   string
	Type string

	// Account is the organization account the event belongs to, resolved from
	// the event's own context. Every projection is scoped by it.
	Account core.AccountRef

	// ObjectID is the id of the object the event is about, when it has one.
	ObjectID string

	// CreatedAt is Stripe's event.created. It orders nothing: the projection
	// guard uses retrieval time instead (see migration 000004). It is kept
	// only because it is useful to a human reading the inbox.
	CreatedAt time.Time

	// Payload is the raw verified body, stored verbatim in the inbox so a
	// projection can be re-derived without asking Stripe again.
	Payload []byte

	// Livemode is Stripe's own statement about which universe this came from.
	Livemode bool
}

// WebhookVerifier turns a raw request body into a verified event. It holds the
// endpoint signing secrets, one per account, because each account's endpoint
// is configured separately in Stripe and therefore signs with its own secret.
type WebhookVerifier struct {
	secrets      map[core.AccountRef]string
	accountsByID map[string]core.AccountRef
	env          core.StripeEnvironment
}

// NewWebhookVerifier builds the verifier. Both accounts must have a secret:
// an account whose events cannot be verified is an account whose events would
// have to be dropped, and silently dropping settlement events is the failure
// this whole milestone exists to prevent.
func NewWebhookVerifier(env core.StripeEnvironment, membershipsSecret, donationsSecret, membershipsAccountID, donationsAccountID string) (*WebhookVerifier, error) {
	switch {
	case env.IsZero():
		return nil, errors.New("stripepay: a Stripe environment is required")
	case membershipsSecret == "" || donationsSecret == "":
		return nil, errors.New("stripepay: both webhook signing secrets are required")
	case membershipsSecret == donationsSecret:
		return nil, errors.New("stripepay: the two accounts must have different signing secrets")
	case membershipsAccountID == "" || donationsAccountID == "":
		return nil, errors.New("stripepay: both Stripe account IDs are required")
	}
	return &WebhookVerifier{
		secrets: map[core.AccountRef]string{
			core.Memberships: membershipsSecret,
			core.Donations:   donationsSecret,
		},
		accountsByID: map[string]core.AccountRef{
			membershipsAccountID: core.Memberships,
			donationsAccountID:   core.Donations,
		},
		env: env,
	}, nil
}

// Verify authenticates a webhook body against the named account's signing
// secret and returns the event.
//
// The account is decided by the caller — from the URL path, one endpoint per
// account — and then checked against what the event says about itself, so a
// correctly-signed event delivered to the wrong endpoint is refused rather
// than projected into the wrong ledger. That check is the whole reason the
// portal runs two endpoints instead of one.
func (v *WebhookVerifier) Verify(account core.AccountRef, body []byte, signatureHeader string) (Event, error) {
	secret, ok := v.secrets[account]
	if !ok {
		return Event{}, fmt.Errorf("stripepay: no signing secret for %q", account.String())
	}
	raw, err := webhook.ConstructEvent(body, signatureHeader, secret)
	if err != nil {
		// stripe-go returns one error type for both, so the message is the only
		// discriminator available. Getting this wrong costs an operator hours,
		// so it is worth the string match.
		if strings.Contains(err.Error(), "API version") {
			return Event{}, fmt.Errorf("%w (expected %s): %v",
				ErrAPIVersionMismatch, ExpectedAPIVersion, err)
		}
		return Event{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// The event names its own account in Context. It must be the one whose
	// secret just verified it.
	if raw.Context != "" {
		claimed, known := v.accountsByID[raw.Context]
		if !known {
			return Event{}, fmt.Errorf("stripepay: event %s names unknown account %q", raw.ID, raw.Context)
		}
		if claimed != account {
			return Event{}, fmt.Errorf("stripepay: event %s belongs to %q but arrived on the %q endpoint",
				raw.ID, claimed.String(), account.String())
		}
	}

	// Livemode must match the universe this process runs in. A live event
	// reaching a sandbox process (or the reverse) means an endpoint is
	// misconfigured, and projecting it would mix real and test money.
	if raw.Livemode != v.env.IsLive() {
		return Event{}, fmt.Errorf("stripepay: event %s livemode=%t reached the %s environment",
			raw.ID, raw.Livemode, v.env.String())
	}

	event := Event{
		ID:        raw.ID,
		Type:      string(raw.Type),
		Account:   account,
		CreatedAt: time.Unix(raw.Created, 0).UTC(),
		Payload:   body,
		Livemode:  raw.Livemode,
	}
	if raw.Data != nil {
		if id, ok := raw.Data.Object["id"].(string); ok {
			event.ObjectID = id
		}
	}
	return event, nil
}

// Object returns the event's decoded object. The payload is verified, so
// reading it is safe; *acting* on it is not, which is why the projector
// re-retrieves the canonical object from Stripe before writing anything. This
// exists to read the identifiers that tell the projector what to retrieve.
func (e Event) Object() (map[string]any, error) {
	var envelope struct {
		Data struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(e.Payload, &envelope); err != nil {
		return nil, fmt.Errorf("stripepay: decode event %s: %w", e.ID, err)
	}
	return envelope.Data.Object, nil
}
