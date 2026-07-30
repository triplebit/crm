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

	// IMEICiphertext is a cryptox.PII envelope. There is deliberately no
	// shipping-address field: Stripe holds addresses, the portal does not.
	IMEICiphertext string

	CheckoutSessionID    string
	CheckoutURLExpiresAt *time.Time
	IdempotencyKey       string

	// CreatedAt bounds how long a pending order may be resumed: past the
	// inventory hold window it is stale, and resurrecting it could hand out a
	// payable Checkout page with no stock behind it.
	CreatedAt time.Time
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
		                    currency, imei_ciphertext, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, 'checkout_pending', $6, NULLIF($7, ''), $8)
	`, o.ID, o.UserID, o.Program, o.Environment.String(), o.Account.String(),
		o.Currency, o.IMEICiphertext, o.IdempotencyKey)
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
		       COALESCE(imei_ciphertext, ''), created_at,
		       stripe_checkout_session_id, checkout_url_expires_at, idempotency_key
		FROM orders
		WHERE user_id = $1 AND program = $2 AND environment = $3
		  AND state = 'checkout_pending'
	`, userID, program, env.String()).Scan(
		&o.ID, &o.UserID, &o.Program, &account, &o.State, &o.Currency,
		&o.IMEICiphertext, &o.CreatedAt,
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

// Abandon marks a pending order expired and releases every hold it took.
//
// CALLERS MUST PASS A TRANSACTION. It makes four writes, and a partial
// application is worse than none: the first write moves the order out of
// checkout_pending, so a retry reports false and never repairs the rest,
// leaving stock reserved for an order nobody can pay. Idempotent as a whole —
// an order already out of checkout_pending affects no rows — but only atomic
// if the caller made it so.
func (r *Repo) Abandon(ctx context.Context, q db.Conn, orderID uuid.UUID, at time.Time, reason string) (bool, error) {
	tag, err := q.Exec(ctx, `
		UPDATE orders SET state = 'expired', updated_at = now()
		WHERE id = $1 AND state = 'checkout_pending'
	`, orderID)
	if err != nil {
		return false, fmt.Errorf("orders: abandon %s: %w", orderID, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	// Give the stock back before marking the reservation released, so a crash
	// between the two leaves stock reserved rather than double-issued: the
	// safe direction.
	if _, err := q.Exec(ctx, `
		UPDATE inventory i SET reserved = i.reserved - r.quantity, updated_at = now()
		FROM inventory_reservations r
		JOIN order_lines l ON l.id = r.order_line_id
		WHERE r.inventory_id = i.id AND l.order_id = $1 AND r.state = 'held'
	`, orderID); err != nil {
		return false, fmt.Errorf("orders: release stock for %s: %w", orderID, db.Normalize(err))
	}
	if _, err := q.Exec(ctx, `
		UPDATE inventory_reservations r
		SET state = 'released', released_at = $2, updated_at = now()
		FROM order_lines l
		WHERE l.id = r.order_line_id AND l.order_id = $1 AND r.state = 'held'
	`, orderID, at); err != nil {
		return false, fmt.Errorf("orders: release reservations for %s: %w", orderID, db.Normalize(err))
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO order_state_history (id, order_id, from_state, to_state, reason, source)
		VALUES ($1, $2, 'checkout_pending', 'expired', $3, 'system')
	`, uuid.New(), orderID, reason); err != nil {
		return false, fmt.Errorf("orders: record abandonment: %w", db.Normalize(err))
	}
	return true, nil
}

// ByCheckoutSession finds the order a Stripe Checkout Session belongs to.
// Settlement arrives naming a session, so this is the projector's entry point.
func (r *Repo) ByCheckoutSession(ctx context.Context, q db.Conn, env core.StripeEnvironment, account core.AccountRef, sessionID string) (Order, error) {
	o := Order{Environment: env, Account: account}
	err := q.QueryRow(ctx, `
		SELECT id, user_id, program, state, currency,
		       COALESCE(imei_ciphertext, ''), created_at, idempotency_key
		FROM orders
		WHERE environment = $1 AND account_ref = $2 AND stripe_checkout_session_id = $3
	`, env.String(), account.String(), sessionID).Scan(
		&o.ID, &o.UserID, &o.Program, &o.State, &o.Currency,
		&o.IMEICiphertext, &o.CreatedAt, &o.IdempotencyKey,
	)
	if err != nil {
		return Order{}, fmt.Errorf("orders: order for session %s: %w", sessionID, db.Normalize(err))
	}
	o.CheckoutSessionID = sessionID
	return o, nil
}

// Settle records that money arrived: the order becomes paid, its Stripe
// identifiers are stored, and its held reservations become committed stock.
//
// Idempotent by state. The WHERE clause admits only checkout_pending, so a
// replayed event — Stripe retries, and the same settlement can be reached by
// more than one event type — affects no rows the second time and reports
// false. That is the whole replay defence: not a dedup table, just a state
// machine that only moves forward.
func (r *Repo) Settle(ctx context.Context, q db.Conn, orderID uuid.UUID, paymentIntentID, subscriptionID, invoiceID string, at time.Time) (bool, error) {
	tag, err := q.Exec(ctx, `
		UPDATE orders
		SET state = 'paid',
		    paid_at = $2,
		    stripe_payment_intent_id = COALESCE(NULLIF($3, ''), stripe_payment_intent_id),
		    stripe_subscription_id   = COALESCE(NULLIF($4, ''), stripe_subscription_id),
		    stripe_invoice_id        = COALESCE(NULLIF($5, ''), stripe_invoice_id),
		    updated_at = now()
		WHERE id = $1 AND state = 'checkout_pending'
	`, orderID, at, paymentIntentID, subscriptionID, invoiceID)
	if err != nil {
		return false, fmt.Errorf("orders: settle %s: %w", orderID, db.Normalize(err))
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	// Held stock becomes committed: it has been paid for and is owed to a
	// member. inventory.reserved stays as it is — the stock is still not
	// available to anyone else — until fulfillment ships it and decrements
	// on_hand, which is M7's business.
	if _, err := q.Exec(ctx, `
		UPDATE inventory_reservations r
		SET state = 'committed', updated_at = now()
		FROM order_lines l
		WHERE l.id = r.order_line_id AND l.order_id = $1 AND r.state = 'held'
	`, orderID); err != nil {
		return false, fmt.Errorf("orders: commit reservations for %s: %w", orderID, db.Normalize(err))
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO order_state_history (id, order_id, from_state, to_state, reason, source)
		VALUES ($1, $2, 'checkout_pending', 'paid', 'settled by verified webhook', 'stripe')
	`, uuid.New(), orderID); err != nil {
		return false, fmt.Errorf("orders: record settlement: %w", db.Normalize(err))
	}
	return true, nil
}

// ExpiredPending lists pending orders past their window, for the worker to
// abandon one at a time.
//
// It returns identifiers rather than doing the work because abandoning needs a
// transaction per order and a remote call before each one, and a repository is
// the wrong place to own either. The worker composes; this just answers "which
// ones?".
func (r *Repo) ExpiredPending(ctx context.Context, q db.Conn, olderThan time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `
		SELECT id FROM orders
		WHERE state = 'checkout_pending' AND created_at < $1
		ORDER BY created_at
		LIMIT $2
	`, olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("orders: list expired: %w", db.Normalize(err))
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("orders: scan expired: %w", db.Normalize(err))
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("orders: iterate expired: %w", db.Normalize(err))
	}
	return ids, nil
}
