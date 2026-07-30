// Package catalogdb is the repository for the local catalog: the items the
// portal sells and the versioned history of their Stripe prices.
//
// The local catalog is authoritative for what may be sold and at what amount;
// Stripe holds a projection of it. Price history is versioned, never edited:
// a price change closes the current version and opens a new one, so every
// order line can point at the exact version it was sold under, forever.
package catalogdb

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the catalog tables. Stateless; every method takes the
// connection to run on.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// Item mirrors one catalog_items row.
type Item struct {
	ID               uuid.UUID
	Slug             string
	Name             string
	Kind             string
	Program          string
	RequiresShipping bool
	RequiresIMEI     bool
	InventoryTracked bool
	Active           bool
}

// PriceVersion mirrors one catalog_price_versions row: one item's price in
// one Stripe account and environment, over one span of time.
type PriceVersion struct {
	ID            uuid.UUID
	CatalogItemID uuid.UUID
	Environment   core.StripeEnvironment
	Account       core.AccountRef
	ProductID     string
	PriceID       string
	Amount        int64
	Currency      string
	Recurring     bool
	Interval      string // empty when not recurring
	IntervalCount int64  // zero when not recurring
	ActiveFrom    time.Time
	VerifiedAt    *time.Time
}

// UpsertItem creates or refreshes an item, keyed on slug, and returns it.
func (r *Repo) UpsertItem(ctx context.Context, q db.Conn, in Item) (Item, error) {
	var out Item
	err := q.QueryRow(ctx, `
		INSERT INTO catalog_items (
			id, slug, name, kind, program,
			requires_shipping, requires_imei, inventory_tracked, active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
		ON CONFLICT (slug) DO UPDATE SET
			name              = EXCLUDED.name,
			kind              = EXCLUDED.kind,
			program           = EXCLUDED.program,
			requires_shipping = EXCLUDED.requires_shipping,
			requires_imei     = EXCLUDED.requires_imei,
			inventory_tracked = EXCLUDED.inventory_tracked,
			active            = true,
			updated_at        = now()
		RETURNING id, slug, name, kind, program,
		          requires_shipping, requires_imei, inventory_tracked, active
	`, uuid.New(), in.Slug, in.Name, in.Kind, in.Program,
		in.RequiresShipping, in.RequiresIMEI, in.InventoryTracked).
		Scan(&out.ID, &out.Slug, &out.Name, &out.Kind, &out.Program,
			&out.RequiresShipping, &out.RequiresIMEI, &out.InventoryTracked, &out.Active)
	if err != nil {
		return Item{}, fmt.Errorf("catalogdb: upsert item %q: %w", in.Slug, db.Normalize(err))
	}
	return out, nil
}

// CurrentPriceVersion returns the open version for an item in one context, or
// db.ErrNotFound when the item has never been priced there.
func (r *Repo) CurrentPriceVersion(ctx context.Context, q db.Conn, itemID uuid.UUID, env core.StripeEnvironment, account core.AccountRef) (PriceVersion, error) {
	v := PriceVersion{Environment: env, Account: account}
	var interval *string
	var intervalCount *int64
	err := q.QueryRow(ctx, `
		SELECT id, catalog_item_id, stripe_product_id, stripe_price_id,
		       amount, currency, recurring, billing_interval, interval_count,
		       active_from, verified_at
		FROM catalog_price_versions
		WHERE catalog_item_id = $1 AND environment = $2 AND account_ref = $3
		  AND active_until IS NULL
	`, itemID, env.String(), account.String()).Scan(
		&v.ID, &v.CatalogItemID, &v.ProductID, &v.PriceID,
		&v.Amount, &v.Currency, &v.Recurring, &interval, &intervalCount,
		&v.ActiveFrom, &v.VerifiedAt,
	)
	if err != nil {
		return PriceVersion{}, fmt.Errorf("catalogdb: current price for %s: %w", itemID, db.Normalize(err))
	}
	if interval != nil {
		v.Interval = *interval
	}
	if intervalCount != nil {
		v.IntervalCount = *intervalCount
	}
	return v, nil
}

// InsertPriceVersion opens a new version. The partial unique index on
// (item, environment, account) WHERE active_until IS NULL makes two open
// versions for one context impossible; the caller closes the old one first,
// in the same transaction.
func (r *Repo) InsertPriceVersion(ctx context.Context, q db.Conn, v PriceVersion) (uuid.UUID, error) {
	id := uuid.New()
	var interval *string
	var intervalCount *int64
	if v.Recurring {
		interval, intervalCount = &v.Interval, &v.IntervalCount
	}
	_, err := q.Exec(ctx, `
		INSERT INTO catalog_price_versions (
			id, catalog_item_id, environment, account_ref,
			stripe_product_id, stripe_price_id,
			amount, currency, recurring, billing_interval, interval_count,
			active_from
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, id, v.CatalogItemID, v.Environment.String(), v.Account.String(),
		v.ProductID, v.PriceID,
		v.Amount, v.Currency, v.Recurring, interval, intervalCount,
		v.ActiveFrom)
	if err != nil {
		return uuid.Nil, fmt.Errorf("catalogdb: insert price version: %w", db.Normalize(err))
	}
	return id, nil
}

// ClosePriceVersion ends a version at the given instant.
func (r *Repo) ClosePriceVersion(ctx context.Context, q db.Conn, id uuid.UUID, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE catalog_price_versions
		SET active_until = $2
		WHERE id = $1 AND active_until IS NULL
	`, id, at)
	if err != nil {
		return fmt.Errorf("catalogdb: close price version %s: %w", id, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("catalogdb: close price version %s: %w", id, db.ErrNotFound)
	}
	return nil
}

// MarkVerified records that the version was read back from Stripe and
// matched. An unverified version is a version catalog-sync has not proven.
func (r *Repo) MarkVerified(ctx context.Context, q db.Conn, id uuid.UUID, at time.Time, snapshot []byte) error {
	if len(snapshot) == 0 {
		snapshot = []byte("{}")
	}
	tag, err := q.Exec(ctx, `
		UPDATE catalog_price_versions
		SET verified_at = $2, stripe_snapshot = $3
		WHERE id = $1
	`, id, at, snapshot)
	if err != nil {
		return fmt.Errorf("catalogdb: mark version %s verified: %w", id, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("catalogdb: mark version %s verified: %w", id, db.ErrNotFound)
	}
	return nil
}

// OpenVersion pairs an open price version with its item's slug, for the
// retirement pass: sync must see everything that is currently sellable to
// notice what the manifest no longer wants.
type OpenVersion struct {
	Version PriceVersion
	Slug    string
}

// OpenVersions lists every open price version in one Stripe environment,
// across both accounts.
func (r *Repo) OpenVersions(ctx context.Context, q db.Conn, env core.StripeEnvironment) ([]OpenVersion, error) {
	rows, err := q.Query(ctx, `
		SELECT v.id, v.catalog_item_id, v.account_ref,
		       v.stripe_product_id, v.stripe_price_id,
		       v.amount, v.currency, v.recurring, v.billing_interval, v.interval_count,
		       v.active_from, v.verified_at, i.slug
		FROM catalog_price_versions v
		JOIN catalog_items i ON i.id = v.catalog_item_id
		WHERE v.environment = $1 AND v.active_until IS NULL
		ORDER BY i.slug, v.account_ref
	`, env.String())
	if err != nil {
		return nil, fmt.Errorf("catalogdb: list open versions: %w", db.Normalize(err))
	}
	defer rows.Close()

	var out []OpenVersion
	for rows.Next() {
		v := PriceVersion{Environment: env}
		var accountRef string
		var interval *string
		var intervalCount *int64
		var slug string
		if err := rows.Scan(&v.ID, &v.CatalogItemID, &accountRef,
			&v.ProductID, &v.PriceID,
			&v.Amount, &v.Currency, &v.Recurring, &interval, &intervalCount,
			&v.ActiveFrom, &v.VerifiedAt, &slug); err != nil {
			return nil, fmt.Errorf("catalogdb: scan open version: %w", db.Normalize(err))
		}
		account, err := core.ParseAccountRef(accountRef)
		if err != nil {
			return nil, fmt.Errorf("catalogdb: open version %s: %w", v.ID, err)
		}
		v.Account = account
		if interval != nil {
			v.Interval = *interval
		}
		if intervalCount != nil {
			v.IntervalCount = *intervalCount
		}
		out = append(out, OpenVersion{Version: v, Slug: slug})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalogdb: iterate open versions: %w", db.Normalize(err))
	}
	return out, nil
}

// DeactivateItem marks an item unsellable. Its rows and history remain: the
// catalog records what used to be sellable, forever.
func (r *Repo) DeactivateItem(ctx context.Context, q db.Conn, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `
		UPDATE catalog_items SET active = false, updated_at = now() WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("catalogdb: deactivate item %s: %w", id, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("catalogdb: deactivate item %s: %w", id, db.ErrNotFound)
	}
	return nil
}

// ItemBySlug returns one item, active or not — the caller decides what an
// inactive item means for its flow. db.ErrNotFound when the slug is unknown.
func (r *Repo) ItemBySlug(ctx context.Context, q db.Conn, slug string) (Item, error) {
	var out Item
	err := q.QueryRow(ctx, `
		SELECT id, slug, name, kind, program,
		       requires_shipping, requires_imei, inventory_tracked, active
		FROM catalog_items WHERE slug = $1
	`, slug).Scan(&out.ID, &out.Slug, &out.Name, &out.Kind, &out.Program,
		&out.RequiresShipping, &out.RequiresIMEI, &out.InventoryTracked, &out.Active)
	if err != nil {
		return Item{}, fmt.Errorf("catalogdb: item %q: %w", slug, db.Normalize(err))
	}
	return out, nil
}
