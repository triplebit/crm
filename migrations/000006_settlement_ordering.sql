-- One settlement event can legitimately apply to TWO Stripe objects: the
-- Checkout Session it names, and the Subscription whose canonical state its
-- membership write was derived from.
--
-- Until now the application record was unique per event, so settlement could
-- only leave evidence in the Session's ordering domain — and the subscription
-- lifecycle's out-of-order guard, which asks about the SUBSCRIPTION's object
-- id, could never see that a fresher subscription observation had already been
-- written by settlement. Two ordering domains for one membership row is a race:
-- an older canonical subscription read could overwrite a newer one because the
-- guard that should have refused it was looking at a different object id.
--
-- Uniqueness becomes per (event, object): a replayed event is still a no-op
-- for each object it touches, and the guard's question — "has a newer
-- observation of THIS object been applied?" — now has one answer per object,
-- whichever path wrote it.
DO $$
DECLARE
    unique_name text;
BEGIN
    SELECT conname INTO STRICT unique_name
    FROM pg_constraint
    WHERE conrelid = 'stripe_projection_applications'::regclass
      AND contype = 'u';
    EXECUTE format(
        'ALTER TABLE stripe_projection_applications DROP CONSTRAINT %I',
        unique_name);
END
$$;

ALTER TABLE stripe_projection_applications
    ADD CONSTRAINT stripe_projection_applications_event_object_key
    UNIQUE (environment, account_ref, stripe_event_id, object_id);

COMMENT ON CONSTRAINT stripe_projection_applications_event_object_key
    ON stripe_projection_applications IS
    'A replayed event is a no-op per object it touched. Settlement records two '
    'rows for a subscription purchase — the Session it settled and the '
    'Subscription its membership state came from — so every Subscription-derived '
    'membership write shares one ordering domain with the lifecycle events.';
