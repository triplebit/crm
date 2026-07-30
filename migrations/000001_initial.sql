CREATE TABLE users (
    id uuid PRIMARY KEY,
    pocket_id_sub text NOT NULL UNIQUE,
    email text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    email_verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    passkey_prompt_dismissed_at timestamptz
);

CREATE UNIQUE INDEX users_email_normalized_idx ON users (lower(email));

COMMENT ON COLUMN users.passkey_prompt_dismissed_at IS
    'Set when the member dismisses the passkey nudge. A server-side fact about a '
    'person, deliberately not a signed cookie: the cookie form needed a signing '
    'key, an HMAC, a dismissal route and a per-process fallback key, and was '
    'silently rejected by every browser because a __Host- prefixed cookie cannot '
    'carry a non-root Path.';

-- Sessions are server-side and revocable. The browser holds a 32-byte opaque
-- token; this table stores only its SHA-256 digest, so the database contains
-- nothing that can be replayed as a credential.
--
-- One source of truth per fact. Every timestamp lives in a column and nowhere
-- else, and the encrypted envelope holds exactly one thing: 32 random CSRF
-- bytes. The previous implementation stored authenticated_at and
-- absolute_expires_at twice, in a column and inside the envelope's JSON, and
-- required the two copies to be equal on every read. JSON carries nanoseconds
-- and timestamptz carries microseconds, so roughly 999 sessions in 1000 failed
-- to decode and every authenticated request was treated as anonymous. That
-- comparison guarded nothing: expiry is enforced in SQL below, and the AEAD
-- associated data already binds the envelope to this row's token_hash. Here
-- there is no second copy to disagree with, so the bug is unrepresentable
-- rather than fixed.
CREATE TABLE browser_sessions (
    token_hash bytea PRIMARY KEY
        CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_ciphertext text NOT NULL,
    login_method text NOT NULL
        CHECK (login_method IN ('passkey', 'email', 'unknown')),
    authenticated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_reason text NOT NULL DEFAULT '',
    CHECK (authenticated_at <= created_at),
    CHECK (created_at <= last_seen_at),
    CHECK (last_seen_at <= idle_expires_at),
    CHECK (idle_expires_at <= absolute_expires_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

-- Supports revoking every live session for one person in a single statement,
-- which is the force-logout path. The previous implementation had the function
-- but no caller, so no such path existed.
CREATE INDEX browser_sessions_active_user_idx
    ON browser_sessions (user_id, absolute_expires_at)
    WHERE revoked_at IS NULL;

-- Supports the retention sweeper. Sessions were never deleted before, so every
-- historical envelope accumulated indefinitely.
CREATE INDEX browser_sessions_expiry_idx
    ON browser_sessions (LEAST(idle_expires_at, absolute_expires_at))
    WHERE revoked_at IS NULL;

COMMENT ON COLUMN browser_sessions.token_hash IS
    'SHA-256 digest of a 32-byte opaque browser token; the raw token is never stored';
COMMENT ON COLUMN browser_sessions.user_id IS
    'Replaces a hash of the OIDC subject plus a per-request lookup by subject. A '
    'bare UUID is strictly less information than a digest of a Pocket ID subject, '
    'and ON DELETE CASCADE makes erasure-time session removal automatic.';
COMMENT ON COLUMN browser_sessions.csrf_ciphertext IS
    'AES-GCM envelope over 32 random CSRF bytes, with associated data binding it '
    'to this row token_hash. It holds no identifier and no timestamp.';

CREATE TABLE guest_donors (
    id uuid PRIMARY KEY,
    email text NOT NULL DEFAULT '',
    name text NOT NULL DEFAULT '',
    claimed_by_user_id uuid REFERENCES users(id),
    claimed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((claimed_by_user_id IS NULL) = (claimed_at IS NULL))
);

CREATE INDEX guest_donors_email_normalized_idx ON guest_donors (lower(email));

CREATE TABLE staff_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('support', 'fulfillment', 'admin')),
    granted_by_user_id uuid REFERENCES users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (user_id, role)
);

-- Consent is an authorization that can be withdrawn, not a historical log.
--
-- The previous implementation recorded a row only when the box was ticked, but
-- then admitted any prior matching row. A returning donor who deliberately left
-- the box clear still had a Stripe Customer created and shared, and there was no
-- way to withdraw because the table had no column to express it. Its own privacy
-- audit filed that as critical.
--
-- Withdrawal sets withdrawn_at. Re-granting inserts a new row, so the full
-- history survives while at most one grant per (subject, kind, version) is live
-- at any moment. Every gate in the application must test for a live grant at an
-- exact version and content hash, never merely for the existence of a row.
CREATE TABLE consents (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id),
    guest_id uuid REFERENCES guest_donors(id),
    kind text NOT NULL,
    version text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    accepted_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    ip_address inet,
    user_agent text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK ((user_id IS NOT NULL)::integer + (guest_id IS NOT NULL)::integer = 1),
    CHECK (withdrawn_at IS NULL OR withdrawn_at >= accepted_at)
);

-- Partial on withdrawn_at IS NULL: one live grant at a time, unlimited history.
CREATE UNIQUE INDEX consents_user_live_version_idx
    ON consents (user_id, kind, version)
    WHERE user_id IS NOT NULL AND withdrawn_at IS NULL;
CREATE UNIQUE INDEX consents_guest_live_version_idx
    ON consents (guest_id, kind, version)
    WHERE guest_id IS NOT NULL AND withdrawn_at IS NULL;

COMMENT ON COLUMN consents.withdrawn_at IS
    'Non-null once withdrawn. A withdrawn row never authorizes anything; it is '
    'retained so the record of what was agreed, and when, stays intact.';

CREATE TABLE stripe_customers (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id),
    guest_id uuid REFERENCES guest_donors(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    customer_id text NOT NULL CHECK (customer_id ~ '^cus_[A-Za-z0-9]+$'),
    observed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_id IS NOT NULL)::integer + (guest_id IS NOT NULL)::integer = 1),
    UNIQUE (environment, account_ref, customer_id)
);

CREATE UNIQUE INDEX stripe_customers_user_context_idx
    ON stripe_customers (user_id, environment, account_ref) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_customers_guest_context_idx
    ON stripe_customers (guest_id, environment, account_ref) WHERE guest_id IS NOT NULL;

-- A Stripe Customer can outlive the transaction that requested it. Persist
-- the exact request before calling Stripe so a crash after the remote create
-- always resumes in one origin account with one idempotency key.
CREATE TABLE stripe_customer_creation_intents (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    guest_id uuid REFERENCES guest_donors(id) ON DELETE RESTRICT,
    environment text NOT NULL CHECK (
        environment IN ('sandbox', 'production')
    ),
    origin_account_ref text NOT NULL CHECK (
        origin_account_ref IN ('memberships', 'donations')
    ),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 255
    ),
    local_account_id text NOT NULL CHECK (
        char_length(local_account_id) BETWEEN 1 AND 255
    ),
    email text NOT NULL DEFAULT '',
    name text NOT NULL DEFAULT '',
    customer_id text CHECK (
        customer_id IS NULL OR
        customer_id ~ '^cus_[A-Za-z0-9]+$'
    ),
    remote_created_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (user_id IS NOT NULL)::integer +
        (guest_id IS NOT NULL)::integer = 1
    ),
    CHECK (
        (customer_id IS NULL) =
        (remote_created_at IS NULL)
    ),
    UNIQUE (
        environment,
        origin_account_ref,
        idempotency_key
    )
);

CREATE UNIQUE INDEX stripe_customer_creation_intents_user_idx
    ON stripe_customer_creation_intents (user_id, environment)
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_customer_creation_intents_guest_idx
    ON stripe_customer_creation_intents (guest_id, environment)
    WHERE guest_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_customer_creation_intents_customer_idx
    ON stripe_customer_creation_intents (environment, customer_id)
    WHERE customer_id IS NOT NULL;

CREATE TABLE catalog_items (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
    name text NOT NULL,
    sku text NOT NULL DEFAULT '',
    kind text NOT NULL CHECK (
        kind IN ('hotspot_tier', 'friends_tier', 'device', 'gift', 'shipping', 'donation')
    ),
    program text NOT NULL CHECK (program IN ('hotspot', 'friends', 'donation')),
    requires_shipping boolean NOT NULL DEFAULT false,
    requires_imei boolean NOT NULL DEFAULT false,
    inventory_tracked boolean NOT NULL DEFAULT false,
    fair_market_value bigint NOT NULL DEFAULT 0 CHECK (fair_market_value >= 0),
    active boolean NOT NULL DEFAULT true,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE catalog_price_versions (
    id uuid PRIMARY KEY,
    catalog_item_id uuid NOT NULL REFERENCES catalog_items(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_product_id text NOT NULL CHECK (stripe_product_id ~ '^prod_[A-Za-z0-9]+$'),
    stripe_price_id text NOT NULL CHECK (stripe_price_id ~ '^price_[A-Za-z0-9]+$'),
    amount bigint NOT NULL CHECK (amount >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    recurring boolean NOT NULL,
    billing_interval text CHECK (
        billing_interval IS NULL OR billing_interval IN ('day', 'week', 'month', 'year')
    ),
    interval_count integer CHECK (interval_count IS NULL OR interval_count > 0),
    entitlement_feature text NOT NULL DEFAULT '',
    active_from timestamptz NOT NULL,
    active_until timestamptz,
    verified_at timestamptz,
    stripe_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (recurring AND billing_interval IS NOT NULL AND interval_count IS NOT NULL)
        OR
        (NOT recurring AND billing_interval IS NULL AND interval_count IS NULL)
    ),
    CHECK (active_until IS NULL OR active_until > active_from),
    UNIQUE (environment, account_ref, stripe_price_id)
);

CREATE UNIQUE INDEX catalog_price_versions_current_idx
    ON catalog_price_versions (catalog_item_id, environment, account_ref)
    WHERE active_until IS NULL;
CREATE INDEX catalog_price_versions_lookup_idx
    ON catalog_price_versions (environment, account_ref, catalog_item_id, active_from, active_until);

CREATE TABLE inventory (
    id uuid PRIMARY KEY,
    catalog_item_id uuid NOT NULL REFERENCES catalog_items(id),
    variant text NOT NULL DEFAULT '',
    on_hand integer NOT NULL DEFAULT 0 CHECK (on_hand >= 0),
    reserved integer NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    safety_stock integer NOT NULL DEFAULT 0 CHECK (safety_stock >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (catalog_item_id, variant),
    CHECK (reserved <= on_hand)
);

CREATE TABLE orders (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id),
    guest_id uuid REFERENCES guest_donors(id),
    program text NOT NULL CHECK (program IN ('hotspot', 'friends', 'donation')),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    state text NOT NULL CHECK (
        state IN (
            'draft', 'checkout_pending', 'payment_pending', 'paid',
            'fulfillment_pending', 'provisioning', 'shipped', 'complete',
            'expired', 'failed', 'canceled', 'refunded'
        )
    ),
    donation_amount bigint NOT NULL DEFAULT 0 CHECK (donation_amount >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    imei_ciphertext bytea,
    shipping_address_ciphertext bytea,
    stripe_checkout_session_id text,
    stripe_payment_intent_id text,
    stripe_subscription_id text,
    stripe_invoice_id text,
    idempotency_key text NOT NULL,
    gift_declined boolean NOT NULL DEFAULT false,
    checkout_url_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    paid_at timestamptz,
    completed_at timestamptz,
    CHECK ((user_id IS NOT NULL)::integer + (guest_id IS NOT NULL)::integer = 1),
    CHECK (
        (program = 'hotspot' AND account_ref = 'memberships')
        OR
        (program IN ('friends', 'donation') AND account_ref = 'donations')
    ),
    UNIQUE (environment, account_ref, idempotency_key)
);

CREATE UNIQUE INDEX orders_checkout_session_context_idx
    ON orders (environment, account_ref, stripe_checkout_session_id)
    WHERE stripe_checkout_session_id IS NOT NULL;
CREATE UNIQUE INDEX orders_payment_intent_context_idx
    ON orders (environment, account_ref, stripe_payment_intent_id)
    WHERE stripe_payment_intent_id IS NOT NULL;
CREATE UNIQUE INDEX orders_subscription_context_idx
    ON orders (environment, account_ref, stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;
CREATE UNIQUE INDEX orders_invoice_context_idx
    ON orders (environment, account_ref, stripe_invoice_id)
    WHERE stripe_invoice_id IS NOT NULL;
CREATE UNIQUE INDEX orders_one_pending_membership_program_per_user_idx
    ON orders (user_id, program)
    WHERE program IN ('hotspot', 'friends')
      AND user_id IS NOT NULL
      AND state IN (
          'draft', 'checkout_pending', 'payment_pending', 'paid',
          'fulfillment_pending', 'provisioning', 'shipped'
      );
CREATE INDEX orders_user_created_idx ON orders (user_id, created_at DESC);
CREATE INDEX orders_guest_created_idx ON orders (guest_id, created_at DESC);
CREATE INDEX orders_state_idx ON orders (state, created_at);

CREATE TABLE order_lines (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    line_number integer NOT NULL CHECK (line_number > 0),
    catalog_item_id uuid REFERENCES catalog_items(id),
    catalog_price_version_id uuid REFERENCES catalog_price_versions(id),
    kind text NOT NULL CHECK (
        kind IN ('hotspot_tier', 'friends_tier', 'device', 'gift', 'shipping', 'donation')
    ),
    slug text NOT NULL,
    name text NOT NULL,
    sku text NOT NULL DEFAULT '',
    variant text NOT NULL DEFAULT '',
    stripe_product_id text NOT NULL DEFAULT '',
    stripe_price_id text NOT NULL DEFAULT '',
    amount bigint NOT NULL CHECK (amount >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    quantity integer NOT NULL CHECK (quantity > 0),
    requires_shipping boolean NOT NULL DEFAULT false,
    inventory_tracked boolean NOT NULL DEFAULT false,
    fair_market_value bigint NOT NULL DEFAULT 0 CHECK (fair_market_value >= 0),
    eligibility_threshold bigint NOT NULL DEFAULT 0
        CHECK (eligibility_threshold >= 0),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (order_id, line_number)
);

CREATE TABLE inventory_reservations (
    id uuid PRIMARY KEY,
    inventory_id uuid NOT NULL REFERENCES inventory(id),
    order_line_id uuid NOT NULL UNIQUE REFERENCES order_lines(id) ON DELETE RESTRICT,
    quantity integer NOT NULL CHECK (quantity > 0),
    state text NOT NULL CHECK (state IN ('held', 'committed', 'released', 'expired')),
    expires_at timestamptz,
    processing_since timestamptz,
    released_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (
            state = 'held'
            AND (
                expires_at IS NOT NULL
                OR processing_since IS NOT NULL
            )
        )
        OR state <> 'held'
    )
);

CREATE INDEX inventory_reservations_expiry_idx
    ON inventory_reservations (expires_at) WHERE state = 'held';

CREATE TABLE order_state_history (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    from_state text,
    to_state text NOT NULL,
    reason text NOT NULL DEFAULT '',
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX order_state_history_order_idx ON order_state_history (order_id, created_at);

CREATE TABLE memberships (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    program text NOT NULL CHECK (program IN ('hotspot', 'friends')),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    tier_price_version_id uuid NOT NULL REFERENCES catalog_price_versions(id),
    stripe_customer_id text NOT NULL,
    stripe_subscription_id text NOT NULL,
    stripe_schedule_id text,
    status text NOT NULL CHECK (
        status IN (
            'incomplete', 'incomplete_expired', 'trialing', 'active',
            'past_due', 'unpaid', 'paused', 'canceled'
        )
    ),
    provisioning_status text NOT NULL DEFAULT 'not_required' CHECK (
        provisioning_status IN ('not_required', 'pending', 'active', 'suspended', 'deactivated')
    ),
    current_period_start timestamptz,
    current_period_end timestamptz,
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    pending_tier_price_version_id uuid REFERENCES catalog_price_versions(id),
    grace_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (program = 'hotspot' AND account_ref = 'memberships')
        OR
        (program = 'friends' AND account_ref = 'donations')
    ),
    UNIQUE (environment, account_ref, stripe_subscription_id)
);

CREATE UNIQUE INDEX memberships_schedule_context_idx
    ON memberships (environment, account_ref, stripe_schedule_id)
    WHERE stripe_schedule_id IS NOT NULL;
CREATE UNIQUE INDEX memberships_one_live_program_per_user_idx
    ON memberships (user_id, program)
    WHERE status IN ('incomplete', 'trialing', 'active', 'past_due', 'paused');
CREATE INDEX memberships_user_program_idx ON memberships (user_id, program);

-- Persist setup-mode Checkout correlation before redirect so a missed
-- checkout/setup/mandate webhook can be repaired from locally known IDs.
CREATE TABLE stripe_bank_setup_attempts (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    membership_id uuid NOT NULL REFERENCES memberships(id),
    attempt_sequence bigint NOT NULL CHECK (attempt_sequence > 0),
    environment text NOT NULL CHECK (
        environment IN ('sandbox', 'production')
    ),
    account_ref text NOT NULL CHECK (
        account_ref IN ('memberships', 'donations')
    ),
    stripe_customer_id text NOT NULL CHECK (
        stripe_customer_id ~ '^cus_[A-Za-z0-9_]+$'
    ),
    stripe_subscription_id text NOT NULL CHECK (
        stripe_subscription_id ~ '^sub_[A-Za-z0-9_]+$'
    ),
    stripe_checkout_session_id text,
    stripe_setup_intent_id text,
    stripe_mandate_id text,
    idempotency_key text NOT NULL,
    status text NOT NULL DEFAULT 'draft' CHECK (
        status IN (
            'draft', 'checkout_pending', 'complete', 'requires_action',
            'succeeded', 'failed', 'canceled', 'expired'
        )
    ),
    assignment_status text NOT NULL DEFAULT 'not_ready' CHECK (
        assignment_status IN (
            'not_ready', 'pending', 'applied', 'superseded'
        )
    ),
    assignment_applied_at timestamptz,
    assignment_superseded_at timestamptz,
    expires_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, idempotency_key),
    UNIQUE (membership_id, attempt_sequence)
);

CREATE UNIQUE INDEX stripe_bank_setup_attempts_session_context_idx
    ON stripe_bank_setup_attempts (
        environment, account_ref, stripe_checkout_session_id
    )
    WHERE stripe_checkout_session_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_bank_setup_attempts_intent_context_idx
    ON stripe_bank_setup_attempts (
        environment, account_ref, stripe_setup_intent_id
    )
    WHERE stripe_setup_intent_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_bank_setup_attempts_mandate_context_idx
    ON stripe_bank_setup_attempts (
        environment, account_ref, stripe_mandate_id
    )
    WHERE stripe_mandate_id IS NOT NULL;
CREATE UNIQUE INDEX stripe_bank_setup_attempts_one_pending_idx
    ON stripe_bank_setup_attempts (membership_id)
    WHERE status IN (
        'draft', 'checkout_pending', 'complete', 'requires_action'
    );

CREATE TABLE donations (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL UNIQUE REFERENCES orders(id) ON DELETE RESTRICT,
    user_id uuid REFERENCES users(id),
    guest_id uuid REFERENCES guest_donors(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL DEFAULT 'donations' CHECK (account_ref = 'donations'),
    amount bigint NOT NULL CHECK (amount > 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    stripe_payment_intent_id text,
    settled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_id IS NOT NULL)::integer + (guest_id IS NOT NULL)::integer = 1)
);

CREATE UNIQUE INDEX donations_payment_intent_context_idx
    ON donations (environment, account_ref, stripe_payment_intent_id)
    WHERE stripe_payment_intent_id IS NOT NULL;

CREATE TABLE payment_attempts (
    id uuid PRIMARY KEY,
    order_id uuid REFERENCES orders(id),
    membership_id uuid REFERENCES memberships(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_payment_intent_id text NOT NULL,
    stripe_invoice_id text NOT NULL DEFAULT '',
    stripe_subscription_id text NOT NULL DEFAULT '',
    stripe_customer_id text NOT NULL DEFAULT '',
    stripe_charge_id text NOT NULL DEFAULT '',
    payment_method_type text NOT NULL DEFAULT '',
    status text NOT NULL,
    amount bigint NOT NULL CHECK (amount >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    processing_since timestamptz,
    terminal_at timestamptz,
    failure_code text NOT NULL DEFAULT '',
    failure_message text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, stripe_payment_intent_id)
);

CREATE INDEX payment_attempts_invoice_context_idx
    ON payment_attempts (environment, account_ref, stripe_invoice_id)
    WHERE stripe_invoice_id <> '';
CREATE INDEX payment_attempts_subscription_context_idx
    ON payment_attempts (environment, account_ref, stripe_subscription_id)
    WHERE stripe_subscription_id <> '';
CREATE INDEX payment_attempts_processing_idx
    ON payment_attempts (processing_since)
    WHERE status = 'processing' AND processing_since IS NOT NULL;

CREATE TABLE invoices (
    id uuid PRIMARY KEY,
    membership_id uuid REFERENCES memberships(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_invoice_id text NOT NULL,
    stripe_subscription_id text,
    stripe_payment_intent_id text NOT NULL DEFAULT '',
    stripe_customer_id text NOT NULL DEFAULT '',
    status text NOT NULL,
    billing_reason text NOT NULL DEFAULT '',
    amount_due bigint NOT NULL CHECK (amount_due >= 0),
    amount_paid bigint NOT NULL CHECK (amount_paid >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    period_start timestamptz,
    period_end timestamptz,
    paid_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, stripe_invoice_id)
);

CREATE INDEX invoices_subscription_context_idx
    ON invoices (environment, account_ref, stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;
CREATE INDEX invoices_payment_intent_context_idx
    ON invoices (environment, account_ref, stripe_payment_intent_id)
    WHERE stripe_payment_intent_id <> '';

CREATE TABLE refunds (
    id uuid PRIMARY KEY,
    order_id uuid REFERENCES orders(id),
    donation_id uuid REFERENCES donations(id),
    membership_id uuid REFERENCES memberships(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_refund_id text NOT NULL,
    stripe_payment_intent_id text NOT NULL DEFAULT '',
    stripe_charge_id text NOT NULL DEFAULT '',
    amount bigint NOT NULL CHECK (amount > 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    status text NOT NULL,
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, stripe_refund_id)
);

CREATE INDEX refunds_payment_intent_context_idx
    ON refunds (environment, account_ref, stripe_payment_intent_id)
    WHERE stripe_payment_intent_id <> '';
CREATE INDEX refunds_charge_context_idx
    ON refunds (environment, account_ref, stripe_charge_id)
    WHERE stripe_charge_id <> '';

CREATE TABLE disputes (
    id uuid PRIMARY KEY,
    order_id uuid REFERENCES orders(id),
    donation_id uuid REFERENCES donations(id),
    membership_id uuid REFERENCES memberships(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_dispute_id text NOT NULL,
    stripe_charge_id text NOT NULL,
    stripe_payment_intent_id text NOT NULL DEFAULT '',
    amount bigint NOT NULL CHECK (amount > 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    status text NOT NULL,
    reason text NOT NULL DEFAULT '',
    evidence_due_by timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, stripe_dispute_id)
);

CREATE INDEX disputes_payment_intent_context_idx
    ON disputes (environment, account_ref, stripe_payment_intent_id)
    WHERE stripe_payment_intent_id <> '';
CREATE INDEX disputes_charge_context_idx
    ON disputes (environment, account_ref, stripe_charge_id);

-- Access revocations are projected separately from financial history so a
-- resolved dispute can be cleared without rewriting the immutable Stripe
-- object record. Unresolved rows are dependency-reconciled once their owning
-- membership arrives.
CREATE TABLE financial_invalidations (
    id uuid PRIMARY KEY,
    membership_id uuid REFERENCES memberships(id),
    order_id uuid REFERENCES orders(id),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    source_type text NOT NULL CHECK (
        source_type IN ('refund', 'dispute', 'payment_intent', 'invoice', 'mandate')
    ),
    source_object_id text NOT NULL,
    active boolean NOT NULL,
    reason text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL,
    resolved_at timestamptz,
    UNIQUE (environment, account_ref, source_type, source_object_id)
);

CREATE INDEX financial_invalidations_membership_active_idx
    ON financial_invalidations (membership_id)
    WHERE active AND membership_id IS NOT NULL;

CREATE TABLE staff_alerts (
    id uuid PRIMARY KEY,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    kind text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('warning', 'critical')),
    status text NOT NULL DEFAULT 'open' CHECK (
        status IN ('open', 'acknowledged', 'resolved')
    ),
    order_id uuid REFERENCES orders(id),
    membership_id uuid REFERENCES memberships(id),
    payment_attempt_id uuid REFERENCES payment_attempts(id),
    reservation_id uuid REFERENCES inventory_reservations(id),
    source_key text NOT NULL,
    title text NOT NULL,
    message text NOT NULL,
    occurred_at timestamptz NOT NULL,
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, source_key)
);

CREATE INDEX staff_alerts_open_idx
    ON staff_alerts (severity, occurred_at)
    WHERE status IN ('open', 'acknowledged');

CREATE TABLE assets (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    source_order_line_id uuid REFERENCES order_lines(id),
    catalog_item_id uuid REFERENCES catalog_items(id),
    status text NOT NULL CHECK (
        status IN ('pending', 'approved', 'active', 'suspended', 'retired')
    ),
    imei_ciphertext bytea,
    serial_number_ciphertext bytea,
    iccid_ciphertext bytea,
    staff_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX assets_user_status_idx ON assets (user_id, status);
CREATE UNIQUE INDEX assets_source_order_line_idx
    ON assets (source_order_line_id)
    WHERE source_order_line_id IS NOT NULL;

CREATE TABLE fulfillments (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES orders(id),
    order_line_id uuid REFERENCES order_lines(id),
    asset_id uuid REFERENCES assets(id),
    type text NOT NULL CHECK (type IN ('shipment', 'provisioning', 'digital')),
    status text NOT NULL CHECK (
        status IN ('pending', 'in_progress', 'shipped', 'complete', 'failed', 'canceled')
    ),
    assigned_to_user_id uuid REFERENCES users(id),
    tracking_number_ciphertext bytea,
    carrier text NOT NULL DEFAULT '',
    staff_notes_ciphertext bytea,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX fulfillments_queue_idx ON fulfillments (status, type, created_at);
CREATE UNIQUE INDEX fulfillments_order_line_type_idx
    ON fulfillments (order_line_id, type)
    WHERE order_line_id IS NOT NULL;
CREATE INDEX fulfillments_asset_idx
    ON fulfillments (asset_id)
    WHERE asset_id IS NOT NULL;

-- Replacement hardware is outside v1 unless fulfillment staff explicitly
-- authorizes it. Asset absence alone is not authorization: an asset can be
-- pending, suspended, or missing because fulfillment is incomplete.
CREATE TABLE hotspot_device_replacement_requirements (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    required_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    source_asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (
        char_length(reason) BETWEEN 3 AND 1000
    ),
    required_at timestamptz NOT NULL,
    resolved_at timestamptz,
    resolved_by_fulfillment_id uuid REFERENCES fulfillments(id)
        ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (resolved_at IS NULL) = (resolved_by_fulfillment_id IS NULL)
    ),
    CHECK (
        resolved_at IS NULL OR resolved_at >= required_at
    )
);

CREATE INDEX hotspot_device_replacement_requirements_active_idx
    ON hotspot_device_replacement_requirements (required_at, user_id)
    WHERE resolved_at IS NULL;

CREATE TABLE entitlement_projections (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_customer_id text NOT NULL,
    feature_key text NOT NULL,
    active boolean NOT NULL,
    source_object_id text NOT NULL DEFAULT '',
    valid_from timestamptz,
    valid_until timestamptz,
    observed_at timestamptz NOT NULL,
    UNIQUE (user_id, environment, account_ref, feature_key)
);

CREATE INDEX entitlement_projections_active_idx
    ON entitlement_projections (user_id, active, valid_until);

CREATE TABLE effective_groups (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_name text NOT NULL CHECK (group_name ~ '^triplebit-[a-z0-9-]+$'),
    active boolean NOT NULL,
    reason jsonb NOT NULL DEFAULT '{}'::jsonb,
    computed_at timestamptz NOT NULL,
    synced_at timestamptz,
    PRIMARY KEY (user_id, group_name)
);

CREATE INDEX effective_groups_unsynced_idx
    ON effective_groups (computed_at) WHERE active AND synced_at IS NULL;

CREATE TABLE webhook_events (
    id uuid PRIMARY KEY,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_event_id text NOT NULL CHECK (stripe_event_id ~ '^evt_[A-Za-z0-9]+$'),
    event_type text NOT NULL,
    object_id text NOT NULL DEFAULT '',
    payload jsonb NOT NULL,
    stripe_created_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT now(),
    processing_state text NOT NULL DEFAULT 'pending' CHECK (
        processing_state IN ('pending', 'processing', 'processed', 'failed', 'ignored')
    ),
    processed_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    UNIQUE (environment, account_ref, stripe_event_id)
);

CREATE INDEX webhook_events_pending_idx
    ON webhook_events (received_at) WHERE processing_state IN ('pending', 'failed');

CREATE TABLE stripe_projection_applications (
    id uuid PRIMARY KEY,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    account_ref text NOT NULL CHECK (account_ref IN ('memberships', 'donations')),
    stripe_event_id text NOT NULL CHECK (stripe_event_id ~ '^evt_[A-Za-z0-9]+$'),
    event_type text NOT NULL,
    signal text NOT NULL,
    object_id text NOT NULL,
    order_id uuid REFERENCES orders(id),
    observed_at timestamptz NOT NULL,
    canonical jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment, account_ref, stripe_event_id)
);

-- Serves the out-of-order guard, which asks "has a newer observation of this
-- same Stripe object already been applied?" on every single event:
--
--   WHERE environment = $1 AND account_ref = $2 AND object_id = $3
--     AND observed_at > $4
--
-- Equality on the first three columns and a range on the fourth. Without this
-- index that question is a sequential scan over a table that only ever grows,
-- once per event; the previous implementation had no index for it.
CREATE INDEX stripe_projection_applications_object_observed_idx
    ON stripe_projection_applications (environment, account_ref, object_id, observed_at DESC);

COMMENT ON COLUMN stripe_projection_applications.canonical IS
    'Minimized Stripe object, retained for a bounded window by the retention '
    'sweeper. It must never contain payment-method, bank or address detail.';

-- Durable, leased cursors for bounded full reconciliation of Stripe objects
-- that the portal already tracks. Each account and object type advances
-- independently, so one unavailable Stripe resource cannot starve the other
-- account or the remaining financial projections.
CREATE TABLE stripe_reconciliation_checkpoints (
    environment text NOT NULL CHECK (
        environment IN ('sandbox', 'production')
    ),
    account_ref text NOT NULL CHECK (
        account_ref IN ('memberships', 'donations')
    ),
    object_type text NOT NULL CHECK (
        object_type IN (
            'checkout.session',
            'setup_intent',
            'mandate',
            'subscription',
            'subscription_schedule',
            'invoice',
            'payment_intent',
            'refund',
            'dispute',
            'entitlements.active_entitlement_summary'
        )
    ),
    cycle_id uuid NOT NULL,
    cursor text NOT NULL DEFAULT '',
    cycle_started_at timestamptz NOT NULL,
    next_run_at timestamptz NOT NULL,
    lease_token uuid,
    leased_until timestamptz,
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (
        consecutive_failures >= 0
    ),
    last_error text NOT NULL DEFAULT '',
    last_completed_cycle_id uuid,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (environment, account_ref, object_type),
    CHECK (
        (lease_token IS NULL AND leased_until IS NULL)
        OR
        (lease_token IS NOT NULL AND leased_until IS NOT NULL)
    )
);

CREATE INDEX stripe_reconciliation_checkpoints_due_idx
    ON stripe_reconciliation_checkpoints (
        environment, next_run_at, account_ref, object_type
    )
    WHERE lease_token IS NULL;

-- Remote-object failures are durable but do not pin a keyset cursor forever.
-- The next complete cycle retries the same locally known ID while later IDs
-- continue to receive repair coverage.
CREATE TABLE stripe_reconciliation_object_failures (
    environment text NOT NULL CHECK (
        environment IN ('sandbox', 'production')
    ),
    account_ref text NOT NULL CHECK (
        account_ref IN ('memberships', 'donations')
    ),
    object_type text NOT NULL CHECK (
        object_type IN (
            'checkout.session',
            'setup_intent',
            'mandate',
            'subscription',
            'subscription_schedule',
            'invoice',
            'payment_intent',
            'refund',
            'dispute',
            'entitlements.active_entitlement_summary'
        )
    ),
    object_id text NOT NULL,
    attempts integer NOT NULL DEFAULT 1 CHECK (attempts > 0),
    last_error text NOT NULL,
    first_failed_at timestamptz NOT NULL,
    last_failed_at timestamptz NOT NULL,
    resolved_at timestamptz,
    PRIMARY KEY (environment, account_ref, object_type, object_id)
);

CREATE TABLE outbox_jobs (
    id uuid PRIMARY KEY,
    queue text NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    state text NOT NULL DEFAULT 'available' CHECK (
        state IN ('available', 'leased', 'completed', 'dead')
    ),
    run_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 12 CHECK (max_attempts > 0),
    lease_token uuid,
    leased_until timestamptz,
    last_error text NOT NULL DEFAULT '',
    deduplication_key text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CHECK (
        (state = 'leased' AND lease_token IS NOT NULL AND leased_until IS NOT NULL)
        OR
        (state <> 'leased' AND lease_token IS NULL AND leased_until IS NULL)
    )
);

CREATE UNIQUE INDEX outbox_jobs_deduplication_idx
    ON outbox_jobs (queue, deduplication_key) WHERE deduplication_key IS NOT NULL;
CREATE INDEX outbox_jobs_claim_idx
    ON outbox_jobs (queue, run_at, created_at)
    WHERE state IN ('available', 'leased');

CREATE TABLE acknowledgments (
    id uuid PRIMARY KEY,
    document_id text NOT NULL UNIQUE,
    document_kind text NOT NULL CHECK (
        document_kind IN ('original', 'refund_correction')
    ),
    order_id uuid NOT NULL REFERENCES orders(id),
    donation_id uuid REFERENCES donations(id),
    revision integer NOT NULL CHECK (revision > 0),
    ein text NOT NULL,
    organization_name text NOT NULL,
    settlement_reference text NOT NULL,
    settled_at timestamptz NOT NULL,
    contribution_date date NOT NULL,
    original_contribution_amount bigint NOT NULL CHECK (
        original_contribution_amount > 0
    ),
    contribution_amount bigint NOT NULL CHECK (contribution_amount >= 0),
    total_refunded bigint NOT NULL DEFAULT 0 CHECK (total_refunded >= 0),
    currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
    goods_services_description text NOT NULL DEFAULT '',
    gift_name text NOT NULL DEFAULT '',
    gift_variant text NOT NULL DEFAULT '',
    fair_market_value bigint NOT NULL DEFAULT 0 CHECK (fair_market_value >= 0),
    deductible_amount bigint NOT NULL CHECK (deductible_amount >= 0),
    wording_snapshot text NOT NULL,
    wording_version text NOT NULL,
    approval_reference text NOT NULL,
    approved_at timestamptz NOT NULL,
    correction_reference text NOT NULL DEFAULT '',
    correction_settled_at timestamptz,
    document_json json NOT NULL,
    snapshot_sha256 text NOT NULL CHECK (
        snapshot_sha256 ~ '^[0-9a-f]{64}$'
    ),
    document_sha256 text NOT NULL CHECK (
        document_sha256 ~ '^[0-9a-f]{64}$'
    ),
    corrected_from_id uuid REFERENCES acknowledgments(id),
    issued_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (order_id, revision),
    CHECK (contribution_amount + total_refunded = original_contribution_amount),
    CHECK (deductible_amount <= contribution_amount),
    CHECK (
        (
            document_kind = 'original'
            AND revision = 1
            AND corrected_from_id IS NULL
            AND total_refunded = 0
            AND correction_reference = ''
            AND correction_settled_at IS NULL
        )
        OR
        (
            document_kind = 'refund_correction'
            AND revision > 1
            AND corrected_from_id IS NOT NULL
            AND total_refunded > 0
            AND correction_reference <> ''
            AND correction_settled_at IS NOT NULL
        )
    )
);

CREATE TABLE acknowledgment_deliveries (
    id uuid PRIMARY KEY,
    acknowledgment_id uuid NOT NULL REFERENCES acknowledgments(id),
    idempotency_key text NOT NULL UNIQUE,
    fingerprint text NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    operation text NOT NULL CHECK (
        operation IN ('issue_original', 'issue_refund_correction', 'staff_resend')
    ),
    recipient text NOT NULL,
    subject text NOT NULL,
    actor_kind text NOT NULL,
    actor_id text NOT NULL,
    reason text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (
        status IN ('leased', 'available', 'failed', 'delivered')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_token uuid,
    leased_until timestamptz,
    message_id text NOT NULL DEFAULT '',
    accepted_at timestamptz,
    failure_code text NOT NULL DEFAULT '',
    requested_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (
            status = 'leased'
            AND lease_token IS NOT NULL
            AND leased_until IS NOT NULL
        )
        OR
        (
            status <> 'leased'
            AND lease_token IS NULL
            AND leased_until IS NULL
        )
    ),
    CHECK (
        (
            status = 'delivered'
            AND message_id <> ''
            AND accepted_at IS NOT NULL
        )
        OR status <> 'delivered'
    )
);

CREATE INDEX acknowledgment_deliveries_claim_idx
    ON acknowledgment_deliveries (status, leased_until, updated_at);
CREATE INDEX acknowledgment_deliveries_document_idx
    ON acknowledgment_deliveries (acknowledgment_id, created_at);

CREATE TABLE donor_notes (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id),
    guest_id uuid REFERENCES guest_donors(id),
    author_user_id uuid NOT NULL REFERENCES users(id),
    body_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_id IS NOT NULL)::integer + (guest_id IS NOT NULL)::integer = 1),
    CHECK (
        octet_length(body_ciphertext) > 0
        AND octet_length(body_ciphertext) <= 32768
    )
);

CREATE INDEX donor_notes_user_created_idx
    ON donor_notes (user_id, created_at DESC, id)
    WHERE user_id IS NOT NULL;
CREATE INDEX donor_notes_guest_created_idx
    ON donor_notes (guest_id, created_at DESC, id)
    WHERE guest_id IS NOT NULL;

CREATE TABLE donor_tags (
    name text PRIMARY KEY CHECK (
        name ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'
        AND length(name) BETWEEN 1 AND 64
    ),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_donor_tags (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag_name text NOT NULL REFERENCES donor_tags(name) ON DELETE RESTRICT,
    assigned_by_user_id uuid NOT NULL REFERENCES users(id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tag_name)
);

CREATE INDEX user_donor_tags_tag_idx
    ON user_donor_tags (tag_name, user_id);

CREATE TABLE guest_donor_tags (
    guest_id uuid NOT NULL REFERENCES guest_donors(id) ON DELETE CASCADE,
    tag_name text NOT NULL REFERENCES donor_tags(name) ON DELETE RESTRICT,
    assigned_by_user_id uuid NOT NULL REFERENCES users(id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (guest_id, tag_name)
);

CREATE INDEX guest_donor_tags_tag_idx
    ON guest_donor_tags (tag_name, guest_id);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    deduplication_key text,
    actor_user_id uuid REFERENCES users(id),
    actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'staff', 'system', 'stripe')),
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    account_ref text CHECK (account_ref IS NULL OR account_ref IN ('memberships', 'donations')),
    before_state jsonb,
    after_state jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip_address inet,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_target_idx ON audit_events (target_type, target_id, occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_user_id, occurred_at DESC);
CREATE UNIQUE INDEX audit_events_deduplication_idx
    ON audit_events (deduplication_key)
    WHERE deduplication_key IS NOT NULL;

CREATE FUNCTION reject_immutable_change() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$;

CREATE TRIGGER order_lines_immutable
    BEFORE UPDATE OR DELETE ON order_lines
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

CREATE TRIGGER order_state_history_immutable
    BEFORE UPDATE OR DELETE ON order_state_history
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

CREATE TRIGGER acknowledgments_immutable
    BEFORE UPDATE OR DELETE ON acknowledgments
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END
$$;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER catalog_items_set_updated_at
    BEFORE UPDATE ON catalog_items FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER stripe_customer_creation_intents_set_updated_at
    BEFORE UPDATE ON stripe_customer_creation_intents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER inventory_set_updated_at
    BEFORE UPDATE ON inventory FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER orders_set_updated_at
    BEFORE UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER inventory_reservations_set_updated_at
    BEFORE UPDATE ON inventory_reservations FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER memberships_set_updated_at
    BEFORE UPDATE ON memberships FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER stripe_bank_setup_attempts_set_updated_at
    BEFORE UPDATE ON stripe_bank_setup_attempts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER payment_attempts_set_updated_at
    BEFORE UPDATE ON payment_attempts FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER invoices_set_updated_at
    BEFORE UPDATE ON invoices FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER refunds_set_updated_at
    BEFORE UPDATE ON refunds FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER disputes_set_updated_at
    BEFORE UPDATE ON disputes FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER staff_alerts_set_updated_at
    BEFORE UPDATE ON staff_alerts FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER assets_set_updated_at
    BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER fulfillments_set_updated_at
    BEFORE UPDATE ON fulfillments FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER hotspot_device_replacement_requirements_set_updated_at
    BEFORE UPDATE ON hotspot_device_replacement_requirements
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER stripe_reconciliation_checkpoints_set_updated_at
    BEFORE UPDATE ON stripe_reconciliation_checkpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER outbox_jobs_set_updated_at
    BEFORE UPDATE ON outbox_jobs FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER acknowledgment_deliveries_set_updated_at
    BEFORE UPDATE ON acknowledgment_deliveries FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- V1 scope markers
--
-- All 40 tables ship in this one migration, but V1 writes only 27 of them. The
-- 13 below are deliberately present and unused.
--
-- They are kept rather than trimmed because the constraints are cross-table.
-- guest_donors, for instance, is referenced by the user-or-guest XOR CHECK on
-- orders, donations, consents, stripe_customers,
-- stripe_customer_creation_intents and donor_notes, plus six partial unique
-- indexes. Dropping it would mean editing all of those, at which point this
-- file stops being the reviewed artifact it was carried forward as. An unwritten
-- table costs one pg_class row; a migration is the one artifact that cannot be
-- iterated on cheaply, so 000001 is frozen after its first apply.
--
-- These comments are the machine-readable source for the layercheck rule that
-- fails the build if V1 code references a deferred table.
-- ---------------------------------------------------------------------------

COMMENT ON TABLE guest_donors IS
    'deferred past V1: guest donations are supported, but the flow that claims a '
    'past guest donation into a new account is not';
COMMENT ON TABLE stripe_bank_setup_attempts IS
    'deferred past V1: ACH. V1 pins payment_method_types to card only';
COMMENT ON TABLE hotspot_device_replacement_requirements IS
    'deferred past V1: re-enrollment policy; on day one nobody has cancelled';
COMMENT ON TABLE entitlement_projections IS
    'deferred past V1: access is a pure function of local membership state, not '
    'of Stripe Entitlements, so there is only one source of truth for access';
COMMENT ON TABLE effective_groups IS
    'deferred past V1: Pocket ID group sync is a push into the identity provider '
    'that nothing in V1 reads back';
COMMENT ON TABLE stripe_reconciliation_checkpoints IS
    'deferred past V1: the full re-observation sweeper. V1 relies on Stripe''s '
    '3-day retry window, the dead-letter queue with manual replay, and the '
    'checkout completion page retrieving its own session';
COMMENT ON TABLE stripe_reconciliation_object_failures IS
    'deferred past V1: see stripe_reconciliation_checkpoints';
COMMENT ON TABLE acknowledgments IS
    'deferred past V1: tax acknowledgment documents. Building part of this '
    'table''s revision chain would be worse than building none of it';
COMMENT ON TABLE acknowledgment_deliveries IS
    'deferred past V1: see acknowledgments';
COMMENT ON TABLE donor_notes IS
    'deferred past V1: donor CRM. Note that this table still lacks the '
    'append-only trigger its documentation claimed it had; add one before use';
COMMENT ON TABLE donor_tags IS
    'deferred past V1: donor CRM';
COMMENT ON TABLE user_donor_tags IS
    'deferred past V1: donor CRM';
COMMENT ON TABLE guest_donor_tags IS
    'deferred past V1: donor CRM';
