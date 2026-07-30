package checkout_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/catalog"
	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/stripetest"
)

// A member can buy every hotspot tier the SHIPPED catalog offers, on a database
// that has only ever had migrations applied.
//
// This test exists because two independent reviewers found the same blocker and
// no existing test could see it: every hotspot tier in catalog.json was marked
// inventory_tracked, orders.Reserve required a stock row with variant='default',
// the schema defaulted that column to ”, and no code ever inserted one. A
// fresh production database therefore refused every single enrolment as "out of
// stock" — while the suite stayed green, because the fixtures set the tracking
// flag to the opposite of what the shipped manifest said.
//
// So the rule this encodes is narrow and load-bearing: the acceptance path reads
// the real catalog.json, not a fixture that agrees with the code. A fixture can
// be wrong in the same direction as the bug. The shipped file cannot.
func TestFreshInstallCanSellEveryShippedHotspotTier(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	repo := catalogdb.New()

	manifest := loadShippedCatalog(t)

	// Load the manifest the way catalog-sync does, minus Stripe: items, then one
	// verified price version each. Verification is what sync would have proven
	// against Stripe; the point here is the local sellability path.
	var tiers []string
	for _, item := range manifest.Items {
		created, err := repo.UpsertItem(ctx, pool.Conn(), catalogdb.Item{
			Slug: item.Slug, Name: item.Name, Kind: item.Kind, Program: item.Program,
			RequiresShipping: item.RequiresShipping, RequiresIMEI: item.RequiresIMEI,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", item.Slug, err)
		}
		t.Cleanup(func() {
			c := context.Background()
			_, _ = pool.Conn().Exec(c,
				`UPDATE catalog_price_versions SET active_until = now()
				 WHERE active_until IS NULL AND catalog_item_id = $1`, created.ID)
		})

		// item.Account() rather than a local program→account map: the manifest
		// already owns that mapping, and a second copy here could disagree with
		// the one catalog-sync uses.
		suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
		version := catalogdb.PriceVersion{
			CatalogItemID: created.ID, Environment: core.StripeProduction,
			Account:   item.Account(),
			ProductID: "prod_" + suffix, PriceID: "price_" + suffix,
			Amount: int64(item.Price.Amount), Currency: item.Price.Currency,
			Recurring: item.Price.Recurring, ActiveFrom: time.Now().UTC(),
		}
		if item.Price.Recurring {
			version.Interval, version.IntervalCount = item.Price.Interval, item.Price.IntervalCount
		}
		versionID, err := repo.InsertPriceVersion(ctx, pool.Conn(), version)
		if err != nil {
			t.Fatalf("seed version for %s: %v", item.Slug, err)
		}
		if err := repo.MarkVerified(ctx, pool.Conn(), versionID, time.Now().UTC(), nil); err != nil {
			t.Fatalf("verify %s: %v", item.Slug, err)
		}
		if item.Kind == "hotspot_tier" {
			tiers = append(tiers, item.Slug)
		}
	}

	if len(tiers) == 0 {
		t.Fatal("the shipped catalog offers no hotspot tiers, so this test asserted nothing")
	}

	// Every tier must reach a Checkout URL, BYOD and with the device add-on.
	// A separate member each time: one pending membership order per person is a
	// schema invariant, not something to work around here.
	for _, slug := range tiers {
		for _, withDevice := range []bool{false, true} {
			person := seedPerson(t, pool)
			cleanupOrders(t, pool, person.UserID)

			req := checkout.EnrollmentRequest{TierSlug: slug, IncludeDevice: withDevice}
			if !withDevice {
				req.IMEI = "356938035643809"
			}
			url, err := svc.StartEnrollment(ctx, person, req)
			if err != nil {
				t.Errorf("tier %s (device=%v) cannot be sold on a fresh install: %v",
					slug, withDevice, err)
				continue
			}
			if url == "" {
				t.Errorf("tier %s (device=%v) produced no checkout URL", slug, withDevice)
			}
		}
	}
}

// loadShippedCatalog parses the repository's real catalog.json through the real
// parser. Reading the file rather than restating it is the whole point: a copy
// would drift toward whatever the code currently does.
func loadShippedCatalog(t *testing.T) catalog.Manifest {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "catalog.json"))
	if err != nil {
		t.Fatalf("read shipped catalog: %v", err)
	}
	defer func() { _ = file.Close() }()

	manifest, err := catalog.Parse(file)
	if err != nil {
		t.Fatalf("the shipped catalog.json does not parse: %v", err)
	}
	return manifest
}
