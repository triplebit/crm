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

// parseCatalogSyncArgs separates the manifest path from the one flag this
// command accepts. Kept as a pure function so the guard is testable.
func parseCatalogSyncArgs(args []string) (path string, confirmLive bool, err error) {
	for _, arg := range args {
		switch {
		case arg == "--yes-production":
			confirmLive = true
		case len(arg) > 0 && arg[0] == '-':
			return "", false, fmt.Errorf("unknown flag %q", arg)
		case path != "":
			return "", false, fmt.Errorf("usage: portal catalog-sync [--yes-production] <manifest.json>")
		default:
			path = arg
		}
	}
	if path == "" {
		return "", false, fmt.Errorf("usage: portal catalog-sync [--yes-production] <manifest.json>")
	}
	return path, confirmLive, nil
}

// runCatalogSync loads a manifest into the local catalog and reconciles
// Stripe toward it. Safe to run repeatedly: an unchanged manifest is a no-op,
// and a sync interrupted anywhere converges on the next run.
func runCatalogSync(ctx context.Context, args []string) error {
	manifestPath, confirmLive, err := parseCatalogSyncArgs(args)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireCatalogSync(); err != nil {
		return err
	}

	// The posture default is production — the right default everywhere else,
	// and exactly the wrong surprise for a command that mutates the money
	// catalog. Live pushes are stated and confirmed, never implied: a
	// production credential set copied into a developer's .env must not be
	// enough on its own. Stripe Prices are immutable, so a mistaken push is
	// manual Dashboard cleanup.
	stripeEnv := core.StripeEnvironmentFor(cfg.Environment)
	fmt.Printf("catalog-sync targets the %s Stripe environment\n", stripeEnv.String())
	if stripeEnv.IsLive() && !confirmLive {
		return fmt.Errorf("refusing to modify the LIVE Stripe catalog without --yes-production")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	file, err := os.Open(manifestPath)
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
