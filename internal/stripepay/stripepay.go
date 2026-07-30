// Package stripepay is the only package that talks to Stripe. Layercheck R5
// makes that a build failure rather than a convention.
//
// It exists to neutralise three hazards verified in stripe-go v86's source
// before adoption:
//
//  1. The library reads response bodies with no size bound. Every request
//     here goes through a transport that caps the response and fails loudly
//     past the cap, so a misbehaving upstream cannot balloon memory.
//  2. The library auto-generates a random Idempotency-Key for any mutating
//     request that lacks one (stripe.go:795 in v86.2.0), which turns a
//     retried crash into a duplicate charge. Every mutating method here
//     requires a caller-supplied key and refuses to proceed without one.
//  3. BackendConfig can carry a default Stripe-Context. It must stay nil:
//     the context names which of the organization's two accounts a call
//     addresses, and a forgotten context must be rejected by Stripe, not
//     silently filled in by a default. The per-call context is derived from
//     a core.AccountRef, which cannot be a typo.
package stripepay

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"triplebit.org/portal/internal/core"
)

// DefaultMaxResponseBytes bounds a Stripe API response. The largest object
// this portal ever retrieves is a Checkout Session with expansions — well
// under a megabyte; four is generous.
const DefaultMaxResponseBytes = 4 << 20

// Options configures the client. APIKey, Environment and both account IDs
// are required.
type Options struct {
	// APIKey is the organization-level secret key. Its prefix must agree
	// with Environment: a live key in a sandbox build (or the reverse) is a
	// construction error, not a runtime surprise.
	APIKey      string
	Environment core.Environment

	// MembershipsAccountID and DonationsAccountID are the acct_ identifiers
	// of the organization's two Stripe accounts, used as the Stripe-Context
	// for calls addressed to each.
	MembershipsAccountID string
	DonationsAccountID   string

	// BaseURL overrides the API endpoint. Tests point it at a local fake;
	// empty means api.stripe.com.
	BaseURL string

	// HTTPClient is optional; the default has a 30-second timeout. Its
	// transport is wrapped with the response cap either way.
	HTTPClient *http.Client

	// MaxResponseBytes defaults to DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

// Client wraps stripe-go behind an AccountRef-first API. Every method takes
// the account immediately after ctx, so "which account?" can never be
// implicit, and every mutating method takes an idempotency key next.
type Client struct {
	sc       *stripe.Client
	accounts map[core.AccountRef]string
}

// New validates the options and builds the client.
func New(opts Options) (*Client, error) {
	switch {
	case opts.APIKey == "":
		return nil, errors.New("stripepay: an API key is required")
	case opts.Environment.IsZero():
		return nil, errors.New("stripepay: an environment is required")
	case opts.MembershipsAccountID == "" || opts.DonationsAccountID == "":
		return nil, errors.New("stripepay: both Stripe account IDs are required")
	case !strings.HasPrefix(opts.MembershipsAccountID, "acct_"),
		!strings.HasPrefix(opts.DonationsAccountID, "acct_"):
		return nil, errors.New("stripepay: Stripe account IDs must start with acct_")
	case opts.MembershipsAccountID == opts.DonationsAccountID:
		return nil, errors.New("stripepay: the two Stripe accounts must be different")
	case opts.MaxResponseBytes < 0:
		return nil, errors.New("stripepay: the response cap must be positive")
	}
	if err := checkKeyEnvironment(opts.APIKey, opts.Environment); err != nil {
		return nil, err
	}

	maxBytes := opts.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	// Copy, so wrapping the transport does not mutate a client the caller
	// shares with something else.
	capped := *httpClient
	inner := capped.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	capped.Transport = &cappedTransport{inner: inner, max: maxBytes}

	// StripeContext is deliberately absent from this config (hazard 3): a
	// call that fails to name its account must be refused remotely, never
	// quietly routed to a default.
	cfg := &stripe.BackendConfig{HTTPClient: &capped}
	if opts.BaseURL != "" {
		cfg.URL = stripe.String(opts.BaseURL)
	}
	sc := stripe.NewClient(opts.APIKey, stripe.WithBackends(stripe.NewBackendsWithConfig(cfg)))

	return &Client{
		sc: sc,
		accounts: map[core.AccountRef]string{
			core.Memberships: opts.MembershipsAccountID,
			core.Donations:   opts.DonationsAccountID,
		},
	}, nil
}

// checkKeyEnvironment refuses a key whose mode disagrees with the configured
// environment. The prefixes are documented Stripe conventions: sk_live_/
// rk_live_ keys move real money.
func checkKeyEnvironment(key string, env core.Environment) error {
	live := strings.HasPrefix(key, "sk_live_") || strings.HasPrefix(key, "rk_live_")
	test := strings.HasPrefix(key, "sk_test_") || strings.HasPrefix(key, "rk_test_")
	switch {
	case !live && !test:
		return errors.New("stripepay: the API key is neither a live nor a test secret key")
	case env.IsProduction() && !live:
		return errors.New("stripepay: production requires a live API key")
	case !env.IsProduction() && !test:
		return errors.New("stripepay: a live API key must not be used outside production")
	}
	return nil
}

// contextFor resolves the Stripe-Context for one of the two accounts.
func (c *Client) contextFor(account core.AccountRef) (string, error) {
	if account.IsZero() {
		return "", errors.New("stripepay: a call named no Stripe account")
	}
	id, ok := c.accounts[account]
	if !ok {
		return "", fmt.Errorf("stripepay: no Stripe account configured for %q", account.String())
	}
	return id, nil
}

// mutationParams builds the base params for a state-changing call. The
// idempotency key is required (hazard 2): without one here, the library
// would invent one, and a crash-retry would no longer deduplicate.
func (c *Client) mutationParams(account core.AccountRef, idempotencyKey string) (stripe.Params, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return stripe.Params{}, errors.New(
			"stripepay: a mutating call requires an explicit idempotency key; the library's auto-generated ones make retries unsafe")
	}
	p, err := c.readParams(account)
	if err != nil {
		return stripe.Params{}, err
	}
	p.IdempotencyKey = stripe.String(idempotencyKey)
	return p, nil
}

// readParams builds the base params for a read.
func (c *Client) readParams(account core.AccountRef) (stripe.Params, error) {
	ctxID, err := c.contextFor(account)
	if err != nil {
		return stripe.Params{}, err
	}
	return stripe.Params{StripeContext: stripe.String(ctxID)}, nil
}

// cappedTransport enforces the response size bound (hazard 1).
type cappedTransport struct {
	inner http.RoundTripper
	max   int64
}

func (t *cappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{inner: resp.Body, remaining: t.max, max: t.max}
	return resp, nil
}

type cappedBody struct {
	inner     io.ReadCloser
	remaining int64
	max       int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, fmt.Errorf("stripepay: response exceeded the %d-byte cap", b.max)
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.inner.Close() }
