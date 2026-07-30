-- Retry scheduling for the webhook inbox.
--
-- The inbox had attempts and a lease but no notion of WHEN an attempt was due.
-- Fail returned a row straight to 'failed', the claim query took anything in
-- ('pending','failed') ordered only by receipt, and the worker looped
-- immediately after a failed attempt. So a Stripe or database blip of about one
-- second consumed all twelve attempts inside a few milliseconds and dead-lettered
-- a legitimate payment — while the roadmap's M6 gate said "a failed job visibly
-- retries with backoff". There was no backoff to be visible.
--
-- One column fixes it, because the ordering and the lease were already right.

ALTER TABLE webhook_events
    ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN webhook_events.next_attempt_at IS
    'The earliest instant this event may be claimed again. Set to receipt time '
    'for a new event (so it is due immediately) and pushed forward by the '
    'inbox''s bounded exponential backoff after each failure. A claim that '
    'ignored this column would turn a transient outage into an exhausted '
    'attempt budget.';

-- The claim index now leads with the due time, because that is the first
-- predicate: "what is due?" then "oldest first". Leading with received_at made
-- every claim scan rows that were not yet due.
DROP INDEX webhook_events_claim_idx;
CREATE INDEX webhook_events_claim_idx
    ON webhook_events (next_attempt_at, received_at)
    WHERE processing_state IN ('pending', 'failed', 'processing');
