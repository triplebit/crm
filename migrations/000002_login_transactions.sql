-- A login transaction is the server-side state of one OIDC sign-in attempt:
-- created when the member is redirected to Pocket ID, consumed exactly once
-- when the callback returns. The browser holds only a 32-byte opaque token;
-- this row keeps the state, nonce and PKCE verifier the callback must check.
--
-- The previous implementation carried these values in an encrypted cookie.
-- A server-side row is preferred for the same reason browser sessions are: the
-- payload never leaves the server, expiry is enforced in SQL rather than by
-- trusting the browser to discard a cookie, and DELETE ... RETURNING makes the
-- transaction single-use by construction instead of by convention.
--
-- Nothing here identifies a person. state, nonce and the verifier are random
-- protocol values that expire within minutes; the row is deleted on use, and
-- abandoned rows are swept by retention.
CREATE TABLE login_transactions (
    token_hash bytea PRIMARY KEY
        CHECK (octet_length(token_hash) = 32),
    state text NOT NULL,
    nonce text NOT NULL,
    pkce_verifier text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (created_at < expires_at)
);

-- Supports the retention sweeper: abandoned sign-in attempts are the common
-- case (closed tab, wrong password at the IdP) and must not accumulate.
CREATE INDEX login_transactions_expiry_idx ON login_transactions (expires_at);

COMMENT ON TABLE login_transactions IS
    'One in-flight OIDC sign-in. Written at redirect, deleted at callback; '
    'rows older than expires_at are dead and swept.';
COMMENT ON COLUMN login_transactions.token_hash IS
    'SHA-256 digest of the opaque token in the login cookie; the raw token is never stored';
