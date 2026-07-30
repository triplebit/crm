// Package stripesync keeps local state and Stripe in agreement. Its first
// job is the catalog push: the manifest is authoritative, the local database
// records what was done, and Stripe is reconciled toward the manifest.
//
// Every remote mutation carries a deterministic idempotency key derived from
// what is being created and what it replaces. That is the crash-recovery
// design: a sync that dies at any point is simply run again, and every step
// either replays to the same result (Stripe deduplicates on the key) or was
// already recorded locally. There is no resume state to store, because the
// procedure converges from the database and manifest alone.
package stripesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/catalog"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/stripepay"
)

// Syncer pushes a manifest into the local catalog and Stripe.
type Syncer struct {
	repo *catalogdb.Repo
	pool *db.Pool
	pay  *stripepay.Client
	env  core.StripeEnvironment
	now  func() time.Time
}

// Options configures a Syncer. Everything is required except Now.
type Options struct {
	Repo        *catalogdb.Repo
	Pool        *db.Pool
	Pay         *stripepay.Client
	Environment core.StripeEnvironment
	Now         func() time.Time
}

// New builds a Syncer, refusing an incomplete configuration.
func New(opts Options) (*Syncer, error) {
	switch {
	case opts.Repo == nil:
		return nil, errors.New("stripesync: a catalog repository is required")
	case opts.Pool == nil:
		return nil, errors.New("stripesync: a database pool is required")
	case opts.Pay == nil:
		return nil, errors.New("stripesync: a Stripe client is required")
	case opts.Environment.IsZero():
		return nil, errors.New("stripesync: a Stripe environment is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Syncer{
		repo: opts.Repo,
		pool: opts.Pool,
		pay:  opts.Pay,
		env:  opts.Environment,
		now:  now,
	}, nil
}

// Result counts what one sync did, for the operator's eyes.
type Result struct {
	Unchanged int
	Created   int
	Rotated   int
	Verified  int
}

func (r Result) String() string {
	return fmt.Sprintf("%d unchanged, %d created, %d rotated, %d verified",
		r.Unchanged, r.Created, r.Rotated, r.Verified)
}

// Sync reconciles the catalog and Stripe toward the manifest. It stops at the
// first item that fails: a partial sync is safe (each item is independent and
// convergent), but continuing past an error would bury it in later output.
func (s *Syncer) Sync(ctx context.Context, m catalog.Manifest) (Result, error) {
	var result Result
	for _, item := range m.Items {
		if err := s.syncItem(ctx, item, &result); err != nil {
			return result, fmt.Errorf("stripesync: item %q: %w", item.Slug, err)
		}
	}
	return result, nil
}

func (s *Syncer) syncItem(ctx context.Context, item catalog.Item, result *Result) error {
	stored, err := s.repo.UpsertItem(ctx, s.pool.Conn(), catalogdb.Item{
		Slug:             item.Slug,
		Name:             item.Name,
		Kind:             item.Kind,
		Program:          item.Program,
		RequiresShipping: item.RequiresShipping,
		RequiresIMEI:     item.RequiresIMEI,
		InventoryTracked: item.InventoryTracked,
	})
	if err != nil {
		return err
	}
	account := item.Account()

	current, err := s.repo.CurrentPriceVersion(ctx, s.pool.Conn(), stored.ID, s.env, account)
	switch {
	case err == nil && versionMatches(current, item.Price):
		// The common case: nothing changed. Verify once if never verified
		// (a previous sync may have died between insert and verification);
		// product display names are deliberately not reconciled here — the
		// price is the load-bearing fact, and a rename takes effect at the
		// next price rotation.
		if current.VerifiedAt == nil {
			if err := s.verify(ctx, account, current, item.Price); err != nil {
				return err
			}
			result.Verified++
		}
		result.Unchanged++
		return nil

	case err == nil:
		// The price changed: create the successor, retire the old price
		// remotely, then swap the versions in one transaction. Run again
		// after a crash at any point, every step replays or no-ops.
		if err := s.rotate(ctx, account, stored, current, item); err != nil {
			return err
		}
		result.Rotated++
		return nil

	case errors.Is(err, db.ErrNotFound):
		if err := s.create(ctx, account, stored, item); err != nil {
			return err
		}
		result.Created++
		return nil

	default:
		return err
	}
}

// create prices an item for the first time in this environment and account.
func (s *Syncer) create(ctx context.Context, account core.AccountRef, stored catalogdb.Item, item catalog.Item) error {
	product, err := s.pay.CreateProduct(ctx, account,
		fmt.Sprintf("catsync:product:%s:%s", s.env.String(), item.Slug),
		stripepay.ProductSpec{Name: item.Name, Slug: item.Slug})
	if err != nil {
		return err
	}
	price, err := s.pay.CreatePrice(ctx, account,
		priceIdempotencyKey(s.env, item.Slug, item.Price, "none"),
		priceSpec(product.ID, item))
	if err != nil {
		return err
	}
	versionID, err := s.repo.InsertPriceVersion(ctx, s.pool.Conn(), version(stored.ID, s.env, account, product.ID, price, s.now()))
	if err != nil {
		return err
	}
	return s.markVerified(ctx, versionID, price, item.Price)
}

// rotate replaces the current price with the manifest's.
func (s *Syncer) rotate(ctx context.Context, account core.AccountRef, stored catalogdb.Item, current catalogdb.PriceVersion, item catalog.Item) error {
	price, err := s.pay.CreatePrice(ctx, account,
		priceIdempotencyKey(s.env, item.Slug, item.Price, current.PriceID),
		priceSpec(current.ProductID, item))
	if err != nil {
		return err
	}
	// Retire the old price before recording the swap: if this crashes
	// mid-way, the next run recreates the same successor (same idempotency
	// key) and deactivating an already-inactive price is a no-op.
	if _, err := s.pay.DeactivatePrice(ctx, account,
		"catsync:deactivate:"+current.PriceID, current.PriceID); err != nil {
		return err
	}

	now := s.now().UTC()
	var versionID uuid.UUID
	err = s.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
		if err := s.repo.ClosePriceVersion(ctx, c, current.ID, now); err != nil {
			return err
		}
		id, err := s.repo.InsertPriceVersion(ctx, c, version(stored.ID, s.env, account, current.ProductID, price, now))
		if err != nil {
			return err
		}
		versionID = id
		return nil
	})
	if err != nil {
		return err
	}
	return s.markVerified(ctx, versionID, price, item.Price)
}

// verify re-reads a price from Stripe and marks the version verified only if
// what Stripe holds is what the database recorded. This is the M4 gate's
// substance: the catalog is authoritative because it is checked, not assumed.
func (s *Syncer) verify(ctx context.Context, account core.AccountRef, v catalogdb.PriceVersion, want catalog.PriceSpec) error {
	remote, err := s.pay.GetPrice(ctx, account, v.PriceID)
	if err != nil {
		return err
	}
	if err := matchesRemote(remote, want); err != nil {
		return err
	}
	snapshot, _ := json.Marshal(remote)
	return s.repo.MarkVerified(ctx, s.pool.Conn(), v.ID, s.now().UTC(), snapshot)
}

func (s *Syncer) markVerified(ctx context.Context, versionID uuid.UUID, remote stripepay.Price, want catalog.PriceSpec) error {
	if err := matchesRemote(remote, want); err != nil {
		return err
	}
	snapshot, _ := json.Marshal(remote)
	return s.repo.MarkVerified(ctx, s.pool.Conn(), versionID, s.now().UTC(), snapshot)
}

// matchesRemote refuses to bless a version whose remote price disagrees with
// the manifest, however that came to be.
func matchesRemote(remote stripepay.Price, want catalog.PriceSpec) error {
	if remote.UnitAmount != int64(want.Amount) ||
		remote.Currency != want.Currency ||
		remote.Recurring != want.Recurring ||
		(want.Recurring && (remote.Interval != want.Interval || remote.IntervalCount != want.IntervalCount)) {
		return fmt.Errorf("stripe price %s does not match the manifest (remote %d %s, manifest %d %s)",
			remote.ID, remote.UnitAmount, remote.Currency, want.Amount, want.Currency)
	}
	if !remote.Active {
		return fmt.Errorf("stripe price %s is inactive but recorded as current", remote.ID)
	}
	return nil
}

func versionMatches(v catalogdb.PriceVersion, want catalog.PriceSpec) bool {
	return v.Amount == int64(want.Amount) &&
		v.Currency == want.Currency &&
		v.Recurring == want.Recurring &&
		(!want.Recurring || (v.Interval == want.Interval && v.IntervalCount == want.IntervalCount))
}

func priceSpec(productID string, item catalog.Item) stripepay.PriceSpec {
	return stripepay.PriceSpec{
		ProductID:     productID,
		Slug:          item.Slug,
		UnitAmount:    int64(item.Price.Amount),
		Currency:      item.Price.Currency,
		Recurring:     item.Price.Recurring,
		Interval:      item.Price.Interval,
		IntervalCount: item.Price.IntervalCount,
	}
}

func version(itemID uuid.UUID, env core.StripeEnvironment, account core.AccountRef, productID string, price stripepay.Price, now time.Time) catalogdb.PriceVersion {
	return catalogdb.PriceVersion{
		CatalogItemID: itemID,
		Environment:   env,
		Account:       account,
		ProductID:     productID,
		PriceID:       price.ID,
		Amount:        price.UnitAmount,
		Currency:      price.Currency,
		Recurring:     price.Recurring,
		Interval:      price.Interval,
		IntervalCount: price.IntervalCount,
		ActiveFrom:    now.UTC(),
	}
}

// priceIdempotencyKey is deterministic over the price's content and the
// price it replaces. Same manifest, same predecessor → same key, so a
// crashed sync replays instead of duplicating. A price changed A→B→A within
// Stripe's idempotency window still gets a fresh key, because the
// predecessor differs.
func priceIdempotencyKey(env core.StripeEnvironment, slug string, spec catalog.PriceSpec, previousPriceID string) string {
	content := fmt.Sprintf("%s|%s|%d|%s|%t|%s|%d|%s",
		env.String(), slug, spec.Amount, spec.Currency,
		spec.Recurring, spec.Interval, spec.IntervalCount, previousPriceID)
	sum := sha256.Sum256([]byte(content))
	return "catsync:price:" + slug + ":" + hex.EncodeToString(sum[:16])
}
