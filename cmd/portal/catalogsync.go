package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"triplebit.org/portal/internal/catalog"
	"triplebit.org/portal/internal/config"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/stripesync"
	"triplebit.org/portal/migrations"
)

// runCatalogSync loads a manifest into the local catalog and reconciles
// Stripe toward it. Safe to run repeatedly: an unchanged manifest is a no-op,
// and a sync interrupted anywhere converges on the next run.
func runCatalogSync(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: portal catalog-sync <manifest.json>")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireCatalogSync(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	file, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	manifest, err := catalog.Parse(file)
	if err != nil {
		return err
	}

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
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
	syncer, err := stripesync.New(stripesync.Options{
		Repo: catalogdb.New(), Pool: pool, Pay: pay, Environment: stripeEnv,
	})
	if err != nil {
		return err
	}

	result, err := syncer.Sync(ctx, manifest)
	if err != nil {
		return err
	}
	fmt.Printf("catalog-sync (%s): %s\n", stripeEnv.String(), result.String())
	return nil
}
