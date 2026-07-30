// Package stripesync keeps local state and Stripe in agreement. Its first
// job is the catalog push: the manifest is authoritative, the local database
// records what was done, and Stripe is reconciled toward the manifest — in
// both directions. Presence creates and updates; absence retires. A slug
// deleted from the manifest stops being sellable, locally and remotely.
//
// Every remote mutation carries a deterministic idempotency key derived from
// what is being created and what it replaces. That is the crash-recovery
// design: a sync that dies at any point is simply run again, and every step
// either replays to the same result (Stripe deduplicates on the key) or was
// already recorded locally. There is no resume state to store, because the
// procedure converges from the database and manifest alone.
//
// verified_at is earned, never assumed: it is set only after the price is
// re-read from Stripe by ID and matches the version — product binding
// included — and the product is re-read, active, and carries the slug that
// created it. A create response is not evidence of what Stripe stored; a
// retrieve is.
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
	Renamed   int
	Retired   int
	Verified  int
}

func (r Result) String() string {
	return fmt.Sprintf("%d unchanged, %d created, %d rotated, %d renamed, %d retired, %d verified",
		r.Unchanged, r.Created, r.Rotated, r.Renamed, r.Retired, r.Verified)
}

// Sync reconciles the catalog and Stripe toward the manifest. It stops at the
// first item that fails: a partial sync is safe (each step is independent and
// convergent), but continuing past an error would bury it in later output.
//
// The whole run holds a per-environment advisory lock. Two concurrent syncs
// with different manifests could otherwise both read the same predecessor,
// create two successors remotely, and race the version swap — the loser's
// successor would stay active in Stripe with no local row referencing it.
// Sequential syncs converge; interleaved ones do not, so interleaving is
// refused.
func (s *Syncer) Sync(ctx context.Context, m catalog.Manifest) (Result, error) {
	var result Result

	// A dedicated session owns the advisory lock for the duration. The
	// remote calls must not run inside a database transaction (WithTx's
	// contract forbids it), so db.TxOptions.Lock is not usable here.
	lockConn, err := s.pool.Pgx().Acquire(ctx)
	if err != nil {
		return result, fmt.Errorf("stripesync: acquire lock session: %w", err)
	}
	lockKey := "catalog-sync:" + s.env.String()
	if _, err := lockConn.Exec(ctx,
		`SELECT pg_advisory_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		lockConn.Release()
		return result, fmt.Errorf("stripesync: lock %q: %w", lockKey, err)
	}
	defer func() {
		// A session lock rides the connection, and Release returns the
		// connection to the pool. If the unlock cannot be proven, the
		// connection must die rather than hand a held lock to the pool's
		// next borrower.
		if _, err := lockConn.Exec(context.Background(),
			`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockKey); err != nil {
			_ = lockConn.Conn().Close(context.Background())
		}
		lockConn.Release()
	}()

	for _, item := range m.Items {
		if err := s.syncItem(ctx, item, &result); err != nil {
			return result, fmt.Errorf("stripesync: item %q: %w", item.Slug, err)
		}
	}
	if err := s.retireAbsent(ctx, m, &result); err != nil {
		return result, err
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
	})
	if err != nil {
		return err
	}
	account := item.Account()

	current, err := s.repo.CurrentPriceVersion(ctx, s.pool.Conn(), stored.ID, s.env, account)
	switch {
	case err == nil:
		// The product is reconciled on every sync — reads are cheap for a
		// catalog this size, and it is what lets a rename converge without
		// waiting for a price change.
		if err := s.reconcileProductName(ctx, account, current.ProductID, item, result); err != nil {
			return err
		}
		if versionMatches(current, item.Price) {
			if current.VerifiedAt == nil {
				if err := s.verify(ctx, account, current.ID, current.PriceID, current.ProductID, item); err != nil {
					return err
				}
				result.Verified++
			}
			result.Unchanged++
			return nil
		}
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

// retireAbsent is the other half of "the manifest is the source of truth":
// any open version whose slug the manifest no longer lists — or whose account
// is no longer where the manifest routes that slug, after a kind change —
// has its remote price retired, its version closed, and (when the slug is
// gone entirely) its item marked unsellable. Run again after a crash at any
// point, every step replays or no-ops: the version is still open, so the
// retirement is found again.
func (s *Syncer) retireAbsent(ctx context.Context, m catalog.Manifest, result *Result) error {
	desired := make(map[string]core.AccountRef, len(m.Items))
	for _, item := range m.Items {
		desired[item.Slug] = item.Account()
	}

	open, err := s.repo.OpenVersions(ctx, s.pool.Conn(), s.env)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	for _, ov := range open {
		wantAccount, present := desired[ov.Slug]
		if present && wantAccount == ov.Version.Account {
			continue
		}
		if _, err := s.pay.DeactivatePrice(ctx, ov.Version.Account,
			deactivationKey(ov.Version.PriceID), ov.Version.PriceID); err != nil {
			return fmt.Errorf("stripesync: retire %q: %w", ov.Slug, err)
		}
		err := s.pool.WithTx(ctx, db.TxOptions{}, func(c db.Conn) error {
			if err := s.repo.ClosePriceVersion(ctx, c, ov.Version.ID, now); err != nil {
				return err
			}
			if !present {
				return s.repo.DeactivateItem(ctx, c, ov.Version.CatalogItemID)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("stripesync: retire %q: %w", ov.Slug, err)
		}
		result.Retired++
	}
	return nil
}

// reconcileProductName keeps Stripe's display name equal to the manifest's.
func (s *Syncer) reconcileProductName(ctx context.Context, account core.AccountRef, productID string, item catalog.Item, result *Result) error {
	product, err := s.pay.GetProduct(ctx, account, productID)
	if err != nil {
		return err
	}
	if product.Name == item.Name {
		return nil
	}
	if _, err := s.pay.UpdateProductName(ctx, account,
		"catsync:rename:"+productID+":"+uuid.New().String(),
		productID, item.Name); err != nil {
		return err
	}
	result.Renamed++
	return nil
}

// create prices an item for the first time in this environment and account.
func (s *Syncer) create(ctx context.Context, account core.AccountRef, stored catalogdb.Item, item catalog.Item) error {
	// The product key includes the name: a crash between the remote create
	// and the local insert, followed by a manifest rename, must not replay
	// the old key with different parameters — Stripe rejects that pairing
	// outright and would wedge the sync for the idempotency window. A fresh
	// key creates a second product and the first sits unreferenced, which
	// converges; a wedged sync does not.
	nameSum := sha256.Sum256([]byte(item.Name))
	product, err := s.pay.CreateProduct(ctx, account,
		fmt.Sprintf("catsync:product:%s:%s:%s:%s",
			s.env.String(), account.String(), item.Slug, hex.EncodeToString(nameSum[:8])),
		stripepay.ProductSpec{Name: item.Name, Slug: item.Slug})
	if err != nil {
		return err
	}
	price, err := s.pay.CreatePrice(ctx, account,
		priceIdempotencyKey(s.env, account, item.Slug, item.Price, product.ID, "none"),
		priceSpec(product.ID, item))
	if err != nil {
		return err
	}
	versionID, err := s.repo.InsertPriceVersion(ctx, s.pool.Conn(), version(stored.ID, s.env, account, product.ID, price, s.now()))
	if err != nil {
		return err
	}
	return s.verify(ctx, account, versionID, price.ID, product.ID, item)
}

// rotate replaces the current price with the manifest's.
func (s *Syncer) rotate(ctx context.Context, account core.AccountRef, stored catalogdb.Item, current catalogdb.PriceVersion, item catalog.Item) error {
	price, err := s.pay.CreatePrice(ctx, account,
		priceIdempotencyKey(s.env, account, item.Slug, item.Price, current.ProductID, current.PriceID),
		priceSpec(current.ProductID, item))
	if err != nil {
		return err
	}
	// Retire the old price before recording the swap: if this crashes
	// mid-way, the next run recreates the same successor (same idempotency
	// key) and deactivating an already-inactive price is a no-op.
	if _, err := s.pay.DeactivatePrice(ctx, account,
		deactivationKey(current.PriceID), current.PriceID); err != nil {
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
	return s.verify(ctx, account, versionID, price.ID, current.ProductID, item)
}

// verify earns verified_at: the price is re-read from Stripe by ID and must
// match the version in every recorded dimension — including which product it
// belongs to — and the product is re-read and must be active and carry the
// slug that created it. A create response never enters this state directly:
// it says what Stripe returned, not what Stripe stored.
func (s *Syncer) verify(ctx context.Context, account core.AccountRef, versionID uuid.UUID, priceID, productID string, item catalog.Item) error {
	remote, err := s.pay.GetPrice(ctx, account, priceID)
	if err != nil {
		return err
	}
	if remote.ID != priceID || remote.ProductID != productID {
		return fmt.Errorf("stripesync: price %s read back as %s under product %s; refusing to verify",
			priceID, remote.ID, remote.ProductID)
	}
	if err := matchesRemote(remote, item.Price); err != nil {
		return err
	}
	product, err := s.pay.GetProduct(ctx, account, productID)
	if err != nil {
		return err
	}
	if !product.Active {
		return fmt.Errorf("stripesync: product %s is inactive; refusing to verify price %s", productID, priceID)
	}
	if product.Slug != item.Slug {
		return fmt.Errorf("stripesync: product %s carries slug %q, want %q; refusing to verify",
			productID, product.Slug, item.Slug)
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

// deactivationKey is fresh per attempt, deliberately. Stripe caches a
// request's result under its idempotency key INCLUDING errors, so retrying a
// failed deactivation on a deterministic key would replay the cached failure
// for the whole retention window — a wedge, not a retry. Deactivation is
// naturally idempotent (inactive twice is inactive), so the key's only job
// is satisfying the wrapper's no-auto-generation rule; deduplication would
// buy nothing. Creates are the opposite case: there the key IS the
// crash-safety, so those stay deterministic and a cached error means the
// sync fails loudly until the window lapses, which is safe.
func deactivationKey(priceID string) string {
	return "catsync:deactivate:" + priceID + ":" + uuid.New().String()
}

// priceIdempotencyKey is deterministic over every create parameter — the
// product included — and the price it replaces. Same manifest, same product,
// same predecessor → same key, so a crashed sync replays instead of
// duplicating; A→B→A within Stripe's idempotency window still gets a fresh
// key because the predecessor differs. The product id earned its place the
// hard way: a key that omits a parameter wedges with idempotency_error the
// first time that parameter diverges, which a local-database rebuild against
// a remembering Stripe demonstrated in practice.
func priceIdempotencyKey(env core.StripeEnvironment, account core.AccountRef, slug string, spec catalog.PriceSpec, productID, previousPriceID string) string {
	content := fmt.Sprintf("%s|%s|%s|%d|%s|%t|%s|%d|%s|%s",
		env.String(), account.String(), slug, spec.Amount, spec.Currency,
		spec.Recurring, spec.Interval, spec.IntervalCount, productID, previousPriceID)
	sum := sha256.Sum256([]byte(content))
	return "catsync:price:" + slug + ":" + hex.EncodeToString(sum[:16])
}
