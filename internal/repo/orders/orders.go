// Package orders is the repository for money-out state: orders, their frozen
// lines, inventory reservations, and the append-only state history.
//
// An order line is a snapshot, not a reference: it copies the amount, name
// and Stripe identifiers from the catalog version it was sold under, so a
// later price change cannot rewrite what a member agreed to pay. The catalog
// answers "what is for sale"; order lines answer "what was sold", forever.
package orders

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
)

// Repo reads and writes the order tables. Stateless; every method takes the
// connection to run on — the checkout service composes them in one
// transaction.
type Repo struct{}

// New returns the repository.
func New() *Repo { return &Repo{} }

// Order mirrors the orders row fields M5 writes.
type Order struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Program     string
	Environment core.StripeEnvironment
	Account     core.AccountRef
	State       string
	Currency    string

	IMEICiphertext            string
	ShippingAddressCiphertext string

	CheckoutSessionID    string
	CheckoutURLExpiresAt *time.Time
	IdempotencyKey       string
}

// Line is one frozen order line.
type Line struct {
	ID                    uuid.UUID
	LineNumber            int
	CatalogItemID         uuid.UUID
	CatalogPriceVersionID uuid.UUID
	Kind                  string
	Slug                  string
	Name                  string
	StripeProductID       string
	StripePriceID         string
	Amount                int64
	Currency              string
	Quantity              int
	RequiresShipping      bool
	InventoryTracked      bool
	Account               core.AccountRef
}

// CreatePending inserts an order in checkout_pending with its lines and the
// state history that got it there, in the caller's transaction. The session
// id is deliberately absent: it does not exist yet, and the gap between this
// commit and storing it is the crash window Resume covers.
func (r *Repo) CreatePending(ctx context.Context, q db.Conn, o Order, lines []Line) error {
	_, err := q.Exec(ctx, `
		INSERT INTO orders (id, user_id, program, environment, account_ref, state,
		                    currency, imei_ciphertext, shipping_address_ciphertext,
		                    idempotency_key)
		VALUES ($1, $2, $3, $4, $5, 'checkout_pending', $6,
		        NULLIF($7, ''), NULLIF($8, ''), $9)
	`, o.ID, o.UserID, o.Program, o.Environment.String(), o.Account.String(),
		o.Currency, o.IMEICiphertext, o.ShippingAddressCiphertext, o.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("orders: create order: %w", db.Normalize(err))
	}
	for _, line := range lines {
		_, err := q.Exec(ctx, `
			INSERT INTO order_lines (id, order_id, line_number, catalog_item_id,
			                         catalog_price_version_id, kind, slug, name,
			                         stripe_product_id, stripe_price_id,
			                         amount, currency, quantity,
			                         requires_shipping, inventory_tracked, account_ref)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		`, line.ID, o.ID, line.LineNumber, nullUUID(line.CatalogItemID),
			nullUUID(line.CatalogPriceVersionID), line.Kind, line.Slug, line.Name,
			line.StripeProductID, line.StripePriceID,
			line.Amount, line.Currency, line.Quantity,
			line.RequiresShipping, line.InventoryTracked, line.Account.String())
		if err != nil {
			return fmt.Errorf("orders: create line %d: %w", line.LineNumber, db.Normalize(err))
		}
	}
	// One history row, telling the truth: the order is born checkout_pending.
	// A synthetic draft→checkout_pending pair would record a state nothing
	// ever observed.
	if _, err := q.Exec(ctx, `
		INSERT INTO order_state_history (id, order_id, from_state, to_state, reason, source)
		VALUES ($1, $2, NULL, 'checkout_pending', 'checkout started', 'member')
	`, uuid.New(), o.ID); err != nil {
		return fmt.Errorf("orders: record state history: %w", db.Normalize(err))
	}
	return nil
}

// Reserve holds inventory for one order line. The schema's
// reserved <= on_hand check is the overselling gate: a reservation that
// would exceed stock fails as db.ErrInvalid, and the caller's whole
// transaction — order included — rolls back.
func (r *Repo) Reserve(ctx context.Context, q db.Conn, lineID, catalogItemID uuid.UUID, quantity int, expiresAt time.Time) error {
	var inventoryID uuid.UUID
	err := q.QueryRow(ctx, `
		UPDATE inventory SET reserved = reserved + $2, updated_at = now()
		WHERE catalog_item_id = $1 AND variant = 'default'
		RETURNING id
	`, catalogItemID, quantity).Scan(&inventoryID)
	if err != nil {
		return fmt.Errorf("orders: reserve stock for item %s: %w", catalogItemID, db.Normalize(err))
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO inventory_reservations (id, inventory_id, order_line_id, quantity, state, expires_at)
		VALUES ($1, $2, $3, $4, 'held', $5)
	`, uuid.New(), inventoryID, lineID, quantity, expiresAt); err != nil {
		return fmt.Errorf("orders: record reservation: %w", db.Normalize(err))
	}
	return nil
}

// AttachSession records the created Checkout Session on the order, closing
// the crash window.
func (r *Repo) AttachSession(ctx context.Context, q db.Conn, orderID uuid.UUID, sessionID string, urlExpiresAt time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE orders
		SET stripe_checkout_session_id = $2, checkout_url_expires_at = $3, updated_at = now()
		WHERE id = $1 AND state = 'checkout_pending'
		  AND (stripe_checkout_session_id IS NULL OR stripe_checkout_session_id = $2)
	`, orderID, sessionID, urlExpiresAt)
	if err != nil {
		return fmt.Errorf("orders: attach session: %w", db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("orders: order %s cannot accept session %s: %w", orderID, sessionID, db.ErrConflict)
	}
	return nil
}

// PendingForUser returns the user's open checkout order for a program, or
// db.ErrNotFound. This is both the resume path and what the one-pending-
// order-per-user index enforces from the schema side.
func (r *Repo) PendingForUser(ctx context.Context, q db.Conn, userID uuid.UUID, program string, env core.StripeEnvironment) (Order, error) {
	o := Order{Environment: env}
	var account string
	var sessionID *string
	err := q.QueryRow(ctx, `
		SELECT id, user_id, program, account_ref, state, currency,
		       COALESCE(imei_ciphertext, ''), COALESCE(shipping_address_ciphertext, ''),
		       stripe_checkout_session_id, checkout_url_expires_at, idempotency_key
		FROM orders
		WHERE user_id = $1 AND program = $2 AND environment = $3
		  AND state = 'checkout_pending'
	`, userID, program, env.String()).Scan(
		&o.ID, &o.UserID, &o.Program, &account, &o.State, &o.Currency,
		&o.IMEICiphertext, &o.ShippingAddressCiphertext,
		&sessionID, &o.CheckoutURLExpiresAt, &o.IdempotencyKey,
	)
	if err != nil {
		return Order{}, fmt.Errorf("orders: pending order for %s: %w", userID, db.Normalize(err))
	}
	parsed, err := core.ParseAccountRef(account)
	if err != nil {
		return Order{}, fmt.Errorf("orders: pending order for %s: %w", userID, err)
	}
	o.Account = parsed
	if sessionID != nil {
		o.CheckoutSessionID = *sessionID
	}
	return o, nil
}

// Lines returns an order's lines in order.
func (r *Repo) Lines(ctx context.Context, q db.Conn, orderID uuid.UUID) ([]Line, error) {
	rows, err := q.Query(ctx, `
		SELECT id, line_number,
		       COALESCE(catalog_item_id, '00000000-0000-0000-0000-000000000000'::uuid),
		       COALESCE(catalog_price_version_id, '00000000-0000-0000-0000-000000000000'::uuid),
		       kind, slug, name, stripe_product_id, stripe_price_id,
		       amount, currency, quantity, requires_shipping, inventory_tracked, account_ref
		FROM order_lines WHERE order_id = $1 ORDER BY line_number
	`, orderID)
	if err != nil {
		return nil, fmt.Errorf("orders: lines for %s: %w", orderID, db.Normalize(err))
	}
	defer rows.Close()

	var out []Line
	for rows.Next() {
		var line Line
		var account string
		if err := rows.Scan(&line.ID, &line.LineNumber, &line.CatalogItemID,
			&line.CatalogPriceVersionID, &line.Kind, &line.Slug, &line.Name,
			&line.StripeProductID, &line.StripePriceID,
			&line.Amount, &line.Currency, &line.Quantity,
			&line.RequiresShipping, &line.InventoryTracked, &account); err != nil {
			return nil, fmt.Errorf("orders: scan line: %w", db.Normalize(err))
		}
		parsed, err := core.ParseAccountRef(account)
		if err != nil {
			return nil, err
		}
		line.Account = parsed
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("orders: iterate lines: %w", db.Normalize(err))
	}
	return out, nil
}

// nullUUID maps the zero UUID to SQL NULL. A line for a member-chosen
// donation amount has no catalog item and no price version — the member set
// the price — and the zero value must reach the database as absence, not as
// a reference to a row that cannot exist.
func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
