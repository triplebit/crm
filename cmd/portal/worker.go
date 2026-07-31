package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/config"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/billing"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/stripesync"
	"triplebit.org/portal/migrations"
)

// runWorker projects received Stripe events into portal state, forever.
//
// This process is what makes settlement independent of anybody looking at a
// page: the web server's only job on delivery is to store the event, and this
// is what acts on it. Two of them can run at once — the claim protocol is FOR
// UPDATE SKIP LOCKED with a lease — which is what makes a rolling deploy safe.
//
// It is built through RequireWorker, so it never holds the session or PII keys.
// The checkout service it needs for the abandonment sweep is constructed with
// no PII keyring at all: abandoning an order touches no personal data, and
// handing this process the means to decrypt some would give away the boundary
// for nothing.
func runWorker(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireWorker(); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Same refusal as the server: a worker running against a schema its binary
	// does not know would project into columns that may not mean what it thinks.
	if err := migrations.Verify(ctx, pool.Pgx()); err != nil {
		return fmt.Errorf("schema is not current: %w", err)
	}

	stripeEnv := core.StripeEnvironmentFor(cfg.Environment)
	pay, err := stripepay.New(stripepay.Options{
		APIKey:               cfg.Stripe.SecretKey,
		Environment:          stripeEnv,
		MembershipsAccountID: cfg.Stripe.MembershipsAccountID,
		DonationsAccountID:   cfg.Stripe.DonationsAccountID,
	})
	if err != nil {
		return err
	}

	ordersRepo := orders.New()
	billingRepo := billing.New()

	// The Abandoner rather than the whole checkout service, because the service
	// requires the PII keyring and releasing inventory needs no personal data.
	// This is the D7 boundary paying for itself: the shape of the dependency is
	// what keeps the key out of this process.
	sweeper, err := checkout.NewAbandoner(ordersRepo, pool, pay, stripeEnv, nil)
	if err != nil {
		return err
	}

	projector, err := stripesync.NewProjector(stripesync.ProjectorOptions{
		Inbox:       inbox.New(),
		Orders:      ordersRepo,
		Billing:     billingRepo,
		Customers:   customers.New(),
		Pool:        pool,
		Pay:         pay,
		Environment: stripeEnv,
	})
	if err != nil {
		return err
	}
	worker, err := stripesync.NewWorker(stripesync.WorkerOptions{
		Projector:   projector,
		Inbox:       inbox.New(),
		Billing:     billingRepo,
		Pool:        pool,
		Sweeper:     sweeper,
		Environment: stripeEnv,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	return worker.Run(ctx)
}
