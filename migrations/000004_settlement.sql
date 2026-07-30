-- M6's schema, batched as one migration per D2.
--
-- Five changes, each answering a specific finding rather than a guess about
-- the future.

-- 1. The webhook inbox gains the lease shape outbox_jobs already has.
--
-- processing_state included 'processing' with nothing to recover it: no lease
-- token, no deadline, no attempt count, and a pending index covering only
-- ('pending','failed'). A worker that died mid-flight therefore stranded a
-- paid order in a state no query would ever find again. The inbox was the
-- outlier; outbox_jobs had this right from the start, so the columns are
-- named to match it rather than invented afresh.
ALTER TABLE webhook_events
    ADD COLUMN attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    ADD COLUMN max_attempts integer NOT NULL DEFAULT 12 CHECK (max_attempts > 0),
    ADD COLUMN lease_token uuid,
    ADD COLUMN leased_until timestamptz,
    ADD CONSTRAINT webhook_events_lease_check CHECK (
        (processing_state = 'processing' AND lease_token IS NOT NULL AND leased_until IS NOT NULL)
        OR
        (processing_state <> 'processing' AND lease_token IS NULL AND leased_until IS NULL)
    );

-- Claiming reads this index; so does the reaper looking for expired leases.
-- 'processing' is included precisely so a stuck row is findable, which is the
-- gap that made the old index a dead end.
DROP INDEX webhook_events_pending_idx;
CREATE INDEX webhook_events_claim_idx
    ON webhook_events (received_at)
    WHERE processing_state IN ('pending', 'failed', 'processing');

COMMENT ON COLUMN webhook_events.leased_until IS
    'A claim expires rather than being held forever: the reaper returns any '
    'lease past this instant to ''pending''. Claims use FOR UPDATE SKIP LOCKED, '
    'so two workers never contend for one row.';

-- 2. payload gets a retention window, because it is the one place raw Stripe
-- detail — billing names, addresses — would otherwise sit in the clear
-- indefinitely. The sibling column stripe_projection_applications.canonical
-- already carries this caveat; the inbox had none.
COMMENT ON COLUMN webhook_events.payload IS
    'The raw Stripe event, retained only until the row is processed and the '
    'retention window elapses (M8''s sweeper, 30 days). It may contain billing '
    'and address detail, so it is never rendered, never logged, and never '
    'copied into a projection.';

-- 3. observed_at is pinned to canonical-retrieval time, not event.created.
--
-- The distinction is load-bearing and was undefined. With event.created, an
-- older event processed later carries fresher canonical data yet is rejected
-- as stale, leaving the projection permanently behind. Retrieval time orders
-- observations by when the portal actually saw Stripe's state, which is the
-- only ordering that makes "has a newer observation been applied?" true.
COMMENT ON COLUMN stripe_projection_applications.observed_at IS
    'When the portal retrieved this object from Stripe — NOT event.created. '
    'The out-of-order guard compares these, and an event delivered late may '
    'still carry the freshest state, so ordering by Stripe''s creation time '
    'would reject exactly the observation that should win.';

-- 4. A custom Friends membership has no catalog price version to anchor.
--
-- The member set the amount, so no catalog_price_versions row describes it —
-- yet tier_price_version_id was NOT NULL, which made a paid custom Friends
-- subscription unprojectable. The immutable order line becomes the anchor
-- instead: it already freezes amount, currency and interval, and unlike a
-- synthesized "current custom price" catalog item it cannot collide with the
-- catalog's single-open-version invariant when two members choose different
-- amounts.
--
-- Exactly one of the two anchors must be present, and a null tier version is
-- permitted only for Friends. Every other combination is refused by the
-- database rather than by remembering.
ALTER TABLE memberships
    ADD COLUMN source_order_line_id uuid REFERENCES order_lines(id),
    ALTER COLUMN tier_price_version_id DROP NOT NULL,
    ADD CONSTRAINT memberships_anchor_check CHECK (
        (tier_price_version_id IS NOT NULL AND source_order_line_id IS NULL)
        OR
        (tier_price_version_id IS NULL AND source_order_line_id IS NOT NULL
            AND program = 'friends')
    );

COMMENT ON COLUMN memberships.source_order_line_id IS
    'The frozen order line a custom-amount Friends membership was sold under, '
    'and its only price anchor. Null for every catalog-priced membership, '
    'which anchors on tier_price_version_id instead.';

-- 5. The three idempotency_key columns that still permitted the empty string.
-- stripe_customer_creation_intents already had this CHECK; these did not, and
-- an empty key is not a key.
ALTER TABLE orders
    ADD CONSTRAINT orders_idempotency_key_check CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 255
    );
ALTER TABLE stripe_bank_setup_attempts
    ADD CONSTRAINT stripe_bank_setup_attempts_idempotency_key_check CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 255
    );
ALTER TABLE acknowledgment_deliveries
    ADD CONSTRAINT acknowledgment_deliveries_idempotency_key_check CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 255
    );
