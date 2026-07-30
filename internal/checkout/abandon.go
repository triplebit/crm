package checkout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
)

// Abandoner retires pending orders that were never paid for.
//
// It is its own small type rather than a pair of Service methods for one
// reason, and it is a privacy reason: the worker has to run this sweep, and
// Service requires the PII keyring. Making the worker construct a Service would
// have meant handing the background process the key that decrypts personal data
// so it could release inventory — which needs no personal data at all. So the
// part both processes share is exactly this, and it holds no key.
//
// The alternative was to reimplement the sweep in the worker. That would have
// duplicated the expire-before-release ordering below, which is the one piece of
// this flow where a mistake charges a member for stock somebody else has.
type Abandoner struct {
	orders *orders.Repo
	pool   *db.Pool
	pay    *stripepay.Client
	env    core.StripeEnvironment
	now    func() time.Time
}

// NewAbandoner builds the sweeper. Now may be nil, meaning time.Now.
func NewAbandoner(ordersRepo *orders.Repo, pool *db.Pool, pay *stripepay.Client,
	env core.StripeEnvironment, now func() time.Time,
) (*Abandoner, error) {
	switch {
	case ordersRepo == nil:
		return nil, errors.New("checkout: an orders repository is required")
	case pool == nil:
		return nil, errors.New("checkout: a database pool is required")
	case pay == nil:
		return nil, errors.New("checkout: a Stripe client is required")
	case env.IsZero():
		return nil, errors.New("checkout: a Stripe environment is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Abandoner{orders: ordersRepo, pool: pool, pay: pay, env: env, now: now}, nil
}

// SweepAbandoned retires every pending order past the resume window, returning
// how many it released.
//
// This closes a gap an audit found in the roadmap rather than in the code: the
// member path abandons its own stale order when someone comes back, so stock
// held by everyone who never comes back was held forever, and a finite pile of
// devices drained to zero with nothing sold.
//
// One order's failure does not stop the others. A Stripe outage must not leave a
// hundred later orders held because the first could not be expired, so each is
// independent and the caller logs what it is told.
func (a *Abandoner) SweepAbandoned(ctx context.Context, limit int) (int, error) {
	stale, err := a.orders.ExpiredPending(ctx, a.pool.Conn(), a.env,
		a.now().UTC().Add(-resumeWindow), limit)
	if err != nil {
		return 0, err
	}
	released := 0
	var problems []error
	for _, order := range stale {
		if err := a.Abandon(ctx, order); err != nil {
			problems = append(problems, fmt.Errorf("order %s: %w", order.ID, err))
			continue
		}
		released++
	}
	return released, errors.Join(problems...)
}

// Abandon retires one stale pending order: unpayable first, then released.
//
// The order of those two steps is the whole safety argument. Releasing stock
// while the hosted page is still payable — Stripe's window is 24 hours, longer
// than resumeWindow — would let a member pay for stock already given to someone
// else. And because Stripe refuses to expire a session that has completed, an
// error here means the money arrived: nothing is released, and the projector
// settles the order instead. The unsafe interleaving is unreachable rather than
// guarded against.
func (a *Abandoner) Abandon(ctx context.Context, order orders.Order) error {
	if order.CheckoutSessionID != "" {
		if err := a.pay.ExpireCheckoutSession(ctx, order.Account,
			"expire:"+order.CheckoutSessionID, order.CheckoutSessionID); err != nil {
			return err
		}
	}
	// One transaction: the four writes Abandon makes must all land or none, or
	// a retry finds the order already out of checkout_pending and never repairs
	// the rest — leaving stock reserved for an order nobody can pay.
	return a.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		_, err := a.orders.Abandon(ctx, c, order.ID, a.now().UTC(),
			"checkout not completed within the reservation window")
		return err
	})
}
