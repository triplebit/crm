package main

import (
	"context"
	"fmt"
	"time"

	"triplebit.org/portal/internal/config"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/migrations"
)

// runMigrate applies pending migrations. It is the only command permitted to
// change the schema, and in production it is the only process given the
// schema-owning database credential: the web and worker processes connect as a
// non-owner role that cannot alter tables or drop the append-only triggers.
func runMigrate(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireMigrate(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := migrations.Migrate(ctx, pool.Pgx()); err != nil {
		return err
	}

	all, err := migrations.All()
	if err != nil {
		return err
	}
	fmt.Printf("PostgreSQL migrations are current (%d applied).\n", len(all))
	return nil
}
