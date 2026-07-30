package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"triplebit.org/portal/internal/config"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/migrations"
)

// parseAvailabilityArgs reads "<slug> in-stock|out-of-stock". A pure function
// so the argument guard is testable without a database.
func parseAvailabilityArgs(args []string) (slug string, available bool, err error) {
	const usage = "usage: portal catalog-availability <slug> in-stock|out-of-stock"
	if len(args) != 2 {
		return "", false, errors.New(usage)
	}
	slug = args[0]
	switch args[1] {
	case "in-stock":
		available = true
	case "out-of-stock":
		available = false
	default:
		return "", false, fmt.Errorf("%s (got %q)", usage, args[1])
	}
	if slug == "" {
		return "", false, errors.New(usage)
	}
	return slug, available, nil
}

// runCatalogAvailability stops or resumes offering one catalog item.
//
// This is the emergency lever, and deliberately the whole of the portal's
// stock story. There is no inventory counter: hotspots come from a supplier
// that does not run out, and the reservation machinery that used to exist made
// a fresh database refuse every enrolment because no stock row existed. What
// remains is a single boolean an operator can flip.
//
// It is a subcommand rather than a staff page because the cases that need it
// are the cases where the web layer may itself be the problem, and it touches
// only the database — no Stripe call, so it works during a Stripe incident,
// which is exactly when "stop selling this" is most needed.
//
// Marking an item out of stock hides it from the offer immediately: every
// sellable query requires catalog_items.active. Orders already paid for are
// untouched — this governs what may be sold next, not what was sold.
func runCatalogAvailability(ctx context.Context, args []string) error {
	slug, available, err := parseAvailabilityArgs(args)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// The same requirement set as catalog-sync minus Stripe: this writes one
	// local boolean and must never need a browser or PII key to do it.
	if err := cfg.RequireCatalogAvailability(); err != nil {
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

	changed, err := catalogdb.New().SetItemAvailability(ctx, pool.Conn(), slug, available)
	if err != nil {
		return err
	}

	state := "out of stock"
	if available {
		state = "in stock"
	}
	if !changed {
		fmt.Fprintf(os.Stdout, "%s was already marked %s; nothing changed\n", slug, state)
		return nil
	}
	fmt.Fprintf(os.Stdout, "%s is now marked %s\n", slug, state)
	if !available {
		fmt.Fprintln(os.Stdout,
			"It has left the offer. Members already in checkout can still pay for "+
				"what they started; catalog-sync will not undo this.")
	}
	return nil
}
