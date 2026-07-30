-- Settle the PII ciphertext representation before the first write freezes it.
--
-- cryptox seals to a text envelope: v1.<key-id>.<base64url>. Seven ciphertext
-- columns were declared bytea — a representation nothing produces — while the
-- one column shipped code writes (browser_sessions.csrf_ciphertext) is text.
-- All become text now, while every one of them is still unwritten.
--
-- The envelope embeds the key id that sealed it, so there is deliberately no
-- key_id column: a second copy of that fact is the mistake that broke every
-- login in the previous implementation (two representations, required equal).
-- rotate-pii selects rows sealed under retired keys through the expression
-- indexes below:
--
--     WHERE <col> IS NOT NULL AND split_part(<col>, '.', 2) <> $active
--     LIMIT $batch
--
-- and needs no cursor table: re-sealing a row removes it from the predicate,
-- so the query is its own resumable cursor. A crash mid-batch loses nothing.
--
-- The CHECK constraints are deliberately shallow (version prefix and two
-- dots), mirroring what cryptox rejects as malformed without freezing its
-- internals into the schema.

-- Preflight: this migration converts types with USING NULL, which is only
-- lossless because the columns are unwritten. That precondition is asserted,
-- not assumed — a database holding any legacy ciphertext refuses the
-- migration loudly instead of destroying PII silently. (No such database
-- exists; the assertion is the difference between knowing that and hoping it.)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM orders
               WHERE imei_ciphertext IS NOT NULL
                  OR shipping_address_ciphertext IS NOT NULL)
       OR EXISTS (SELECT 1 FROM assets
                  WHERE imei_ciphertext IS NOT NULL
                     OR serial_number_ciphertext IS NOT NULL
                     OR iccid_ciphertext IS NOT NULL)
       OR EXISTS (SELECT 1 FROM fulfillments
                  WHERE tracking_number_ciphertext IS NOT NULL
                     OR staff_notes_ciphertext IS NOT NULL)
       OR EXISTS (SELECT 1 FROM donor_notes)
    THEN
        RAISE EXCEPTION 'migration 000003 expects every ciphertext column to be '
            'unwritten; this database holds values the type conversion would destroy';
    END IF;
END $$;

ALTER TABLE orders
    ALTER COLUMN imei_ciphertext TYPE text USING NULL,
    ALTER COLUMN shipping_address_ciphertext TYPE text USING NULL,
    ADD CONSTRAINT orders_imei_envelope_check CHECK (
        imei_ciphertext IS NULL OR imei_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    ),
    ADD CONSTRAINT orders_shipping_envelope_check CHECK (
        shipping_address_ciphertext IS NULL
        OR shipping_address_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    );

ALTER TABLE assets
    ALTER COLUMN imei_ciphertext TYPE text USING NULL,
    ALTER COLUMN serial_number_ciphertext TYPE text USING NULL,
    ALTER COLUMN iccid_ciphertext TYPE text USING NULL,
    ADD CONSTRAINT assets_imei_envelope_check CHECK (
        imei_ciphertext IS NULL OR imei_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    ),
    ADD CONSTRAINT assets_serial_envelope_check CHECK (
        serial_number_ciphertext IS NULL OR serial_number_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    ),
    ADD CONSTRAINT assets_iccid_envelope_check CHECK (
        iccid_ciphertext IS NULL OR iccid_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    );

ALTER TABLE fulfillments
    ALTER COLUMN tracking_number_ciphertext TYPE text USING NULL,
    ALTER COLUMN staff_notes_ciphertext TYPE text USING NULL,
    ADD CONSTRAINT fulfillments_tracking_envelope_check CHECK (
        tracking_number_ciphertext IS NULL OR tracking_number_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    ),
    ADD CONSTRAINT fulfillments_notes_envelope_check CHECK (
        staff_notes_ciphertext IS NULL OR staff_notes_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
    );

-- donor_notes is deferred past V1 but carries the same representation; its
-- length CHECK moves from bytes to characters of envelope text.
ALTER TABLE donor_notes DROP CONSTRAINT donor_notes_body_ciphertext_check;
ALTER TABLE donor_notes
    ALTER COLUMN body_ciphertext TYPE text USING 'v1.placeholder.unwritten',
    ADD CONSTRAINT donor_notes_body_envelope_check CHECK (
        body_ciphertext ~ '^v1\.[^.]+\.[^.]+$'
        AND char_length(body_ciphertext) <= 65536
    );

-- The rotate-pii selection path, one partial expression index per column the
-- portal will write. Cheap while empty; the point is that the pattern is
-- settled once, here, rather than re-invented per milestone.
CREATE INDEX orders_imei_key_idx
    ON orders (split_part(imei_ciphertext, '.', 2))
    WHERE imei_ciphertext IS NOT NULL;
CREATE INDEX orders_shipping_key_idx
    ON orders (split_part(shipping_address_ciphertext, '.', 2))
    WHERE shipping_address_ciphertext IS NOT NULL;
CREATE INDEX assets_imei_key_idx
    ON assets (split_part(imei_ciphertext, '.', 2))
    WHERE imei_ciphertext IS NOT NULL;
CREATE INDEX assets_serial_key_idx
    ON assets (split_part(serial_number_ciphertext, '.', 2))
    WHERE serial_number_ciphertext IS NOT NULL;
CREATE INDEX assets_iccid_key_idx
    ON assets (split_part(iccid_ciphertext, '.', 2))
    WHERE iccid_ciphertext IS NOT NULL;
CREATE INDEX fulfillments_tracking_key_idx
    ON fulfillments (split_part(tracking_number_ciphertext, '.', 2))
    WHERE tracking_number_ciphertext IS NOT NULL;
CREATE INDEX fulfillments_notes_key_idx
    ON fulfillments (split_part(staff_notes_ciphertext, '.', 2))
    WHERE staff_notes_ciphertext IS NOT NULL;

COMMENT ON COLUMN orders.imei_ciphertext IS
    'cryptox text envelope (v1.<key-id>.<base64url>), AAD-bound to this order. '
    'The key id lives only inside the envelope; rotation selects via the '
    'split_part expression index.';
COMMENT ON COLUMN orders.shipping_address_ciphertext IS
    'cryptox text envelope, AAD-bound to this order. See imei_ciphertext.';
