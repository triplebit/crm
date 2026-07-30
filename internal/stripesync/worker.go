package stripesync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/inbox"
)

// Worker timings. The lease comfortably exceeds one event's work (two Stripe
// reads and a transaction); the idle poll is short because settlement latency
// is a member refreshing a page waiting for their membership to appear.
const (
	leaseDuration = 2 * time.Minute
	idlePoll      = 2 * time.Second
	sweepEvery    = 5 * time.Minute
	sweepBatch    = 100
)

// Sweeper abandons pending checkouts nobody completed, returning how many it
// released. checkout.Service implements it.
//
// It is an interface because checkout and stripesync are the same layer, so
// neither may import the other (layercheck R1) — the top-level command wires
// one into the other. The boundary is also the honest one: knowing when a
// checkout is stale, and that it must be made unpayable before its stock is
// released, belongs to the service that created it. The worker owns the clock,
// not the rules.
type Sweeper interface {
	SweepAbandoned(ctx context.Context, limit int) (int, error)
}

// Worker runs the projector in a loop, plus the periodic repairs that keep
// state honest when no event arrives to trigger them.
//
// It is the process that makes M6 true: an order settles because money arrived,
// not because somebody happened to load a page afterwards. It holds no browser
// or PII secrets (D7) — it reads no sessions and decrypts no personal data, and
// config.RequireWorker is prevented by an AST test from even naming those keys.
type Worker struct {
	projector *Projector
	inbox     *inbox.Repo
	billing   *billing.Repo
	pool      *db.Pool
	sweeper   Sweeper
	env       core.StripeEnvironment
	logger    *slog.Logger
	now       func() time.Time

	// interval fields are settable so a test can drive the loop without
	// waiting minutes for a sweep.
	idlePoll   time.Duration
	sweepEvery time.Duration
}

// WorkerOptions configures the worker. Everything except Logger, Now and the
// intervals is required.
type WorkerOptions struct {
	Projector *Projector
	Inbox     *inbox.Repo
	Billing   *billing.Repo
	Pool      *db.Pool
	Sweeper   Sweeper

	Environment core.StripeEnvironment
	Logger      *slog.Logger
	Now         func() time.Time

	IdlePoll   time.Duration
	SweepEvery time.Duration
}

// NewWorker builds the worker, refusing an incomplete configuration.
func NewWorker(opts WorkerOptions) (*Worker, error) {
	switch {
	case opts.Projector == nil:
		return nil, errors.New("stripesync: a projector is required")
	case opts.Inbox == nil, opts.Billing == nil:
		return nil, errors.New("stripesync: the inbox and billing repositories are required")
	case opts.Pool == nil:
		return nil, errors.New("stripesync: a database pool is required")
	case opts.Sweeper == nil:
		return nil, errors.New("stripesync: a sweeper is required")
	case opts.Environment.IsZero():
		return nil, errors.New("stripesync: a Stripe environment is required")
	}
	w := &Worker{
		projector: opts.Projector, inbox: opts.Inbox, billing: opts.Billing,
		pool: opts.Pool, sweeper: opts.Sweeper, env: opts.Environment,
		logger: opts.Logger, now: opts.Now,
		idlePoll: opts.IdlePoll, sweepEvery: opts.SweepEvery,
	}
	if w.logger == nil {
		w.logger = slog.Default()
	}
	if w.now == nil {
		w.now = time.Now
	}
	if w.idlePoll <= 0 {
		w.idlePoll = idlePoll
	}
	if w.sweepEvery <= 0 {
		w.sweepEvery = sweepEvery
	}
	return w, nil
}

// Run processes events until the context is cancelled.
//
// A failure never stops the loop. An event that cannot be projected has already
// been recorded as failed with its cause and returned for a later attempt;
// stopping would starve every other event behind it, which turns one member's
// broken order into everybody's. Permanently failing events become staff alerts
// through the sweep below, so nothing fails quietly forever.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.InfoContext(ctx, "worker started", slog.String("environment", w.env.String()))
	defer w.logger.InfoContext(ctx, "worker stopped")

	nextSweep := w.now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !w.now().Before(nextSweep) {
			w.sweep(ctx)
			nextSweep = w.now().Add(w.sweepEvery)
		}

		worked, err := w.projector.ProcessOne(ctx, leaseDuration)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			w.logger.ErrorContext(ctx, "projecting an event failed", slog.String("error", err.Error()))
		}
		if worked {
			continue // Drain the queue before idling.
		}
		if err := sleep(ctx, w.idlePoll); err != nil {
			return nil
		}
	}
}

// sweep runs the periodic repairs. Each reports its own failure and none can
// prevent the others from running: one broken repair must not silence the rest.
func (w *Worker) sweep(ctx context.Context) {
	now := w.now().UTC()

	// Claims whose worker died. Without this, a 'processing' row is stranded
	// forever and the paid order behind it never settles.
	if reaped, err := w.inbox.ReapExpiredLeases(ctx, w.pool.Conn(), now); err != nil {
		w.logger.ErrorContext(ctx, "reaping expired leases failed", slog.String("error", err.Error()))
	} else if reaped > 0 {
		w.logger.WarnContext(ctx, "returned abandoned event claims", slog.Int64("count", reaped))
	}

	if released, err := w.sweeper.SweepAbandoned(ctx, sweepBatch); err != nil {
		// Partial success is normal here and worth distinguishing: some orders
		// were released, some could not be, and the count says which.
		w.logger.ErrorContext(ctx, "abandoning stale checkouts partly failed",
			slog.Int("released", released), slog.String("error", err.Error()))
	} else if released > 0 {
		w.logger.InfoContext(ctx, "released stale checkouts' stock", slog.Int("count", released))
	}

	w.escalateDeadLetters(ctx, now)
}

// escalateDeadLetters turns events that will never be retried into something a
// person sees.
//
// An event past its attempt budget is otherwise invisible: the money arrived,
// the member has nothing, and no page anywhere is wrong. A dead-letter queue
// nobody reads is not a control, which is why this runs on a timer instead of
// waiting for someone to think of looking. RaiseAlert deduplicates on the
// source key, so re-alerting the same event every five minutes is a no-op.
func (w *Worker) escalateDeadLetters(ctx context.Context, now time.Time) {
	letters, err := w.inbox.DeadLetters(ctx, w.pool.Conn(), w.env, sweepBatch)
	if err != nil {
		w.logger.ErrorContext(ctx, "listing dead letters failed", slog.String("error", err.Error()))
		return
	}
	for _, letter := range letters {
		if err := w.billing.RaiseAlert(ctx, w.pool.Conn(), w.env, letter.Account,
			"webhook_unprocessable", "event:"+letter.StripeID,
			"A Stripe event could not be processed and will not be retried",
			fmt.Sprintf("Event %s (%s) failed %d times and is past its attempt budget. "+
				"Last error: %s", letter.StripeID, letter.Type, letter.Attempts, letter.LastError),
			now); err != nil {
			w.logger.ErrorContext(ctx, "raising a dead-letter alert failed",
				slog.String("event", letter.StripeID), slog.String("error", err.Error()))
		}
	}
	if len(letters) > 0 {
		w.logger.WarnContext(ctx, "events need human attention", slog.Int("count", len(letters)))
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
