# Decision register

Context, decision, consequence — one entry per locked decision, kept short
deliberately. The fuller reasoning lives in the commit that made each change;
`git log` searches are cited where they matter. This file exists because the
commit messages are good and undiscoverable.

## D1 — adopt stripe-go v86

**Context.** The predecessor hand-rolled webhook signature verification,
expandable-ID handling and API pagination: ~2,500 lines that must be perfect.
**Decision.** Use `stripe-go` v86: zero runtime dependencies,
`Params.StripeContext` supports the two-account Organization, verified before
adoption. **Consequence.** Three library hazards must be neutralised in the
wrapper (`internal/stripepay`, M4): no response size cap (wrap the transport),
`BackendConfig.StripeContext` stays nil so a missing context is rejected by
Stripe itself, and auto-generated idempotency keys are forbidden. The
enforcement is layercheck R5 alone — imports of `stripe-go`, test files
included, are a build failure outside the wrapper, and code that cannot
import the library cannot construct its params. There is no separate lint.

## D2 — migrations are append-only, per-file checksummed

**Context.** The schema is the most reviewed artifact in the repo; the
predecessor never applied it to any real database. **Decision.** One initial
migration carried the reviewed 40 tables with edits applied inline; every
applied file is checksummed in the ledger and never edited again; growth is a
new file, applied under an advisory lock. **Consequence.** Schema changes are
naturally batched (see the M6 batch in the roadmap), and `Verify` can prove at
startup that a binary and a database agree exactly.

## D3 — one CSRF token per session, no path binding

**Context.** The predecessor bound tokens to `"METHOD /path"`, which forced
three parallel hardcoded path lists, seven minting sites and 15 HMACs per page
render — against a threat that requires already holding the victim's token.
**Decision.** One HMAC-derived token per session, read from `r.PostForm` only,
behind a global Origin check, `SameSite=Lax` and `__Host-` cookies.
**Consequence.** One minting site, one validation site, and the token can
never arrive in a URL.

## D4 — one source of truth per fact

**Context.** The predecessor stored session timestamps twice (column and
encrypted JSON) and required them equal; nanosecond-vs-microsecond precision
made ~999 in 1000 sessions fail to decode. Login was broken from the first
commit. **Decision.** Every fact lives in exactly one place: timestamps in
columns, the envelope holds only the 32-byte CSRF secret, expiry is enforced
in the SQL `WHERE` clause. **Consequence.** The class of bug is
unrepresentable, not fixed. The pattern repeats everywhere: prices resolve
from the catalog snapshot, access from local projections, money from
settlement events.

## D5 — guest donations ship; the claim flow defers

**Context.** The predecessor's claim link carried the donor's email in a
signed-but-unencrypted URL parameter, and its replay nonce was never stored.
**Decision.** Guests can donate in V1; attaching a past guest donation to a
new account is deferred. **Consequence.** The dangerous surface (a bearer link
that discloses PII) is not built at all until it can be built as an opaque
server-side token, which `internal/tokens` now provides the shape for.

## D6 — access is a pure function of local state

**Context.** Stripe Entitlements would make Stripe a second source of truth
for who may use the service. **Decision.** Access derives entirely from
PostgreSQL projections that only verified webhooks update. **Consequence.**
The checkout return page grants nothing; a member's `/account` can be
explained by querying one database; Stripe outages degrade payments, never
access.

## D7 — one binary with subcommands

**Context.** The predecessor had three binaries and two config loaders that
drifted. **Decision.** `portal serve|worker|migrate|...`, one config loader,
per-subcommand `Require*()` validation. **Consequence.** The worker container
is never handed browser-session or PII keys (an AST test enforces that
`RequireWorker` cannot even reference them), and the migrate credential can
own the schema while serve's cannot.

## D8 — a mutating route cannot be registered unprotected

**Context.** CSRF-by-discipline fails the first time someone adds a handler
in a hurry. **Decision.** Handlers are `func(*reqctx) error`, not
`http.HandlerFunc`; the registrar offers exactly `get`, `getLimited`,
`getAuthed`, `post`; `post` bundles session + parsed-form + CSRF checks with
no variant lacking them; impossible flag combinations panic at startup.
**Consequence.** Tests iterate the route registry, so every future mutating
route is covered the moment it compiles. `router.Webhook` will be the single
greppable exception when M6 needs it; until then no exception exists.

## D9 — the portal stores no shipping addresses

**Context.** Stripe collects the shipping address on the hosted Checkout page
and keeps it on the settled session indefinitely. The worker is deliberately
denied the PII key (D7), so a design where the worker projected addresses into
`orders.shipping_address_ciphertext` would have forced either weakening that
boundary or building an encrypt-only mechanism — the symmetric AES-GCM keyring
cannot encrypt without also being able to decrypt. **Decision.** Do not store
shipping addresses at all. Stripe is the system of record; staff read the
address from Stripe at the moment they print a label. **Consequence.** The
portal holds zero home addresses: nothing to encrypt, rotate, sweep, or leak,
and D7's boundary needs no revision. `orders.shipping_address_ciphertext` is
never written and can be dropped in M8. The cost is one Stripe read on the
staff fulfillment page, which is already loading that order.

## D10 — order-field PII goes through cryptox.PII, never a local AAD

**Context.** M5's first draft sealed the IMEI with a private `orderAAD` helper
inside `internal/checkout`, duplicating a record/field codec that
`internal/cryptox` already provided — and leaving M7 (staff reads) and M8
(rotation) unable to open those envelopes without copying the format.
**Decision.** Every order-field ciphertext uses `cryptox.PII`, whose associated
data binds record id and field name. **Consequence.** One codec, in the lowest
layer that can hold it; the private helper is deleted. Copying an envelope
between orders or between fields still fails authentication, which was the
original point.
