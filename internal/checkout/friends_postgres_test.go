package checkout_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/stripetest"
)

// seedFriendsTier is the donations-account sibling of seedTier: a fixed
// monthly Friends option, nothing physical.
func seedFriendsTier(t *testing.T, pool *db.Pool, slug string, cents int64) catalogdb.Item {
	t.Helper()
	ctx := context.Background()
	repo := catalogdb.New()

	_, _ = pool.Conn().Exec(ctx, `
		UPDATE catalog_price_versions SET active_until = now()
		WHERE active_until IS NULL
		  AND catalog_item_id IN (SELECT id FROM catalog_items WHERE slug = $1)
	`, slug)

	item, err := repo.UpsertItem(ctx, pool.Conn(), catalogdb.Item{
		Slug: slug, Name: "Friends " + slug, Kind: "friends_tier", Program: "friends",
	})
	if err != nil {
		t.Fatalf("seed friends item: %v", err)
	}
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")
	versionID, err := repo.InsertPriceVersion(ctx, pool.Conn(), catalogdb.PriceVersion{
		CatalogItemID: item.ID,
		Environment:   core.StripeProduction,
		Account:       core.Donations,
		ProductID:     "prod_" + suffix,
		PriceID:       "price_" + suffix,
		Amount:        cents, Currency: "usd",
		Recurring: true, Interval: "month", IntervalCount: 1,
		ActiveFrom: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed friends version: %v", err)
	}
	if err := repo.MarkVerified(ctx, pool.Conn(), versionID, time.Now().UTC(), nil); err != nil {
		t.Fatalf("verify friends version: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Conn().Exec(c, `
			UPDATE catalog_price_versions SET active_until = now()
			WHERE active_until IS NULL AND catalog_item_id = $1
		`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_price_versions WHERE catalog_item_id = $1`, item.ID)
		_, _ = pool.Conn().Exec(c, `DELETE FROM catalog_items WHERE id = $1`, item.ID)
	})
	return item
}

func TestStartFriendsWithAFixedTier(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	tier := seedFriendsTier(t, pool, "friends-"+uuid.New().String()[:8], 2500)
	cleanupOrders(t, pool, person.UserID)

	url, err := svc.StartFriends(ctx, person, checkout.FriendsRequest{TierSlug: tier.Slug})
	if err != nil {
		t.Fatalf("StartFriends: %v", err)
	}
	if url == "" {
		t.Fatal("no checkout URL")
	}

	var program, account, sessionID string
	var amount int64
	var priceID string
	if err := pool.Conn().QueryRow(ctx, `
		SELECT o.program, o.account_ref, COALESCE(o.stripe_checkout_session_id, ''),
		       l.amount, l.stripe_price_id
		FROM orders o JOIN order_lines l ON l.order_id = o.id
		WHERE o.user_id = $1
	`, person.UserID).Scan(&program, &account, &sessionID, &amount, &priceID); err != nil {
		t.Fatalf("read order: %v", err)
	}
	if program != "friends" || account != "donations" {
		t.Errorf("order routed to %s/%s, want friends/donations", program, account)
	}
	if amount != 2500 || priceID == "" {
		t.Errorf("line amount=%d price=%q; a fixed tier must carry the catalog price", amount, priceID)
	}
	if got := fake.Session(sessionID, "mode"); got != "subscription" {
		t.Errorf("session mode = %q, want subscription", got)
	}
}

// The one place an amount legitimately comes from the browser. It is parsed
// to exact cents, bounded, and frozen on the line with no price version —
// because the member set the price, so there is no version to point at.
func TestStartFriendsWithACustomAmount(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	cleanupOrders(t, pool, person.UserID)

	if _, err := svc.StartFriends(ctx, person, checkout.FriendsRequest{CustomAmount: "12.50"}); err != nil {
		t.Fatalf("StartFriends: %v", err)
	}

	var amount int64
	var priceID, slug string
	var versionID *uuid.UUID
	if err := pool.Conn().QueryRow(ctx, `
		SELECT l.amount, l.stripe_price_id, l.slug, l.catalog_price_version_id
		FROM order_lines l JOIN orders o ON o.id = l.order_id
		WHERE o.user_id = $1
	`, person.UserID).Scan(&amount, &priceID, &slug, &versionID); err != nil {
		t.Fatalf("read line: %v", err)
	}
	if amount != 1250 {
		t.Errorf("amount = %d cents, want 1250: dollars must parse exactly", amount)
	}
	if priceID != "" || versionID != nil {
		t.Errorf("a custom amount referenced a catalog price (%q / %v); the member set it", priceID, versionID)
	}
	if slug != "friends-custom" {
		t.Errorf("slug = %q", slug)
	}
}

func TestStartFriendsRejectsUnusableAmounts(t *testing.T) {
	ctx := context.Background()
	fake := stripetest.New(t)
	svc, pool := newService(t, fake)
	person := seedPerson(t, pool)
	cleanupOrders(t, pool, person.UserID)

	for name, amount := range map[string]string{
		"empty":      "",
		"words":      "twelve",
		"negative":   "-5.00",
		"too small":  "0.50",
		"too large":  "5000.00",
		"float trap": "12.505",
	} {
		if _, err := svc.StartFriends(ctx, person, checkout.FriendsRequest{CustomAmount: amount}); err == nil {
			t.Errorf("%s (%q): accepted", name, amount)
		} else if !safeerr.IsSafe(err) || safeerr.StatusOf(err, 0) != http.StatusUnprocessableEntity {
			t.Errorf("%s (%q): unhelpful error %v", name, amount, err)
		}
	}
	if fake.SessionCount() != 0 {
		t.Error("a rejected amount reached Stripe")
	}
}
