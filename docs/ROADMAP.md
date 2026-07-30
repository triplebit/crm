# Triplebit Portal — rebuild roadmap

Progress tracker for the rebuild. Every milestone ends in a command a human runs
whose output is the gate — never "wrote package X".

**Status: M6 next.**

| | Milestone | Gate | Status |
|---|---|---|---|
| M0 | Repo can prove itself | CI green on GitHub | ✅ done |
| M1 | Schema, migrations, `WithTx` | migrate twice; 40 tables; real 40001 retried | ✅ done |
| M2 | Leaf packages | their tests, plus layering clean | ✅ done |
| M3 | A real member can sign in | sign in through Pocket ID, land on `/account` | ✅ done |
| M4 | The catalog is authoritative | `catalog-sync` against a Stripe sandbox | ✅ done |
| M5 | Money out | a real test card reaches Stripe Checkout | ✅ done |
| M6 | Money in, durably | the order settles by itself, replay-safe | ⬜ next |
| M7 | Staff can fulfill | the launch sentence, one person, one sitting | ⬜ |
| M8 | Deploy, rotation, privacy | clean VPS, live Stripe, a real $1 donation | ⬜ |
| M9 | Tax acknowledgments | a refund produces a correction revision | ⬜ |

## The launch sentence

This is the acceptance test for M7, verbatim:

> A member signs in with Pocket ID, enrols in a hotspot membership tier with a
> device, and pays by card in Stripe Checkout. Separately, a one-time card
> donation succeeds. Staff sees the order in a fulfillment queue, records the
> device, and marks it shipped. The member's `/account` reflects all of it, and
> nothing in that chain was granted by a page load — only by a verified webhook.

## Why this rebuild exists

The previous implementation (kept locally in `OLD/`, not tracked here) produced
40,272 lines of non-test Go, 22,977 of test, a 1,171-line schema and 7,583 lines
of documentation in about 27 hours across 25 commits. It never worked.

- Login was broken from the first commit: the session decoder compared
  nanosecond-precision JSON against microsecond-precision `timestamptz`, so
  roughly 999 sessions in 1000 failed to decode and every authenticated request
  was treated as anonymous.
- **No CI job ever ran `go build` or `go test`.** The only workflow was security
  scanners, every one of them `continue-on-error: true`.
- Database tests called `t.Skip` when `PORTAL_TEST_DATABASE_URL` was unset, and
  CI never set it, so the suite reported success while running none of them.
  Four integration tests stayed broken from the baseline commit onward.

The schema, the migration runner and a handful of leaf packages were genuinely
good and are carried forward. What was wrong was the seams.

## Milestones in detail

### M0 — repo skeleton ✅

CI with no `continue-on-error`; every CI gate is a `make` target, and
`make check` is the offline subset (CI additionally runs `test-db`, `vuln` and
`compose-check`); `layercheck` makes the package layering a build failure;
`internal/core` with `AccountRef` and `Environment` as opaque types whose zero
value panics.

### M1 — schema, migrations, transactions ✅

40 tables ported with four reviewed edits applied inline. Schema frozen at
`15376d94ce0636dceeebb7a3b0b1a866a1e782bcb6eaa013d74411e94850a4bb`.

1. `browser_sessions` redesigned so the login bug is unrepresentable.
2. `consents` gained `withdrawn_at`; consent is an authorization, not a log.
3. `users.passkey_prompt_dismissed_at` replaced a cookie browsers rejected.
4. An index for the out-of-order projection guard, which had none.

`internal/db` provides one `Conn` interface where there were six, and `WithTx`
makes serialization-failure retry a field rather than a project.

### M2 — leaf packages ✅

Ported `safeerr`, `cryptox`, `httpx` and the CSRF primitives; added `cookie`,
`tokens`, `money` and `redact`.

- **Fixed an X-Forwarded-For denial of service.** One malformed entry rejected
  the whole header and fell back to the network peer, which is Caddy — so about
  twenty poisoned requests shared one rate-limit bucket and locked every user
  out of login and checkout for ten minutes. The regression test was confirmed
  to fail against the original implementation first.
- **Dropped CSRF path binding**, which had forced three parallel hardcoded path
  lists and a 200-line render function while defending against a threat that
  requires already holding the victim's token. Also switched from `FormValue`
  to `PostForm`, so a token can no longer be supplied in a URL.
- **Deleted `httpx.Cookie`.** It exposed `Path` and `Domain` as caller fields,
  which is how a `__Host-` cookie came to be set with `Path=/account` and was
  silently discarded by every browser. No exported type in `internal/cookie`
  has a `Path` field, and `make lint-cookie` fails the build on any other
  `Set-Cookie` writer.
- **`redact`** makes personal data a type that renders as `[redacted]` through
  every standard-library path, with compile-time proof each interface is
  implemented. Disclosure requires a greppable `.Reveal()`.

### M3 — a real member can sign in ✅

The milestone the previous implementation never reached: the owner signed in
through Pocket ID with a passkey and landed on `/account` showing their own
name, served by the compose stack.

Highlights. Sessions replace four sequential per-request round trips with one
statement. The OIDC login transaction is a server-side single-use row, so a
replayed callback finds nothing to match. Scopes are a package constant —
`groups` cannot be configured, so authorization stays in PostgreSQL. The
router's mutating routes cannot be registered without session + CSRF (D8),
proven by tests that iterate the route registry. A dropped rotation key fails
loud instead of silently signing members out. And Pocket ID is addressed as
`pocket-id.localhost` because WebAuthn refuses to register passkeys outside a
secure context — a bug caught only by walking the real first-run setup.

### M4 — the catalog is authoritative ✅

The browser submits slugs and dollar strings only. The server resolves prices
from an allowlisted catalog snapshot and parses cents itself, with no float.

Gate passed against the real sandbox Organization: `catalog-sync` created all
eight items — hotspot tiers and device in the memberships account, the four
Friends tiers in the donations account — every local version was verified by
reading the price back from Stripe, and the immediate re-run reported
"8 unchanged, 0 created". Stripe refused an organization key carrying no
Stripe-Context, which is the exact remote fail-closed behaviour the wrapper's
design assumed.

### M5 — money out ✅

Order draft → inventory reservation → Stripe Checkout Session → attach →
redirect. Includes the crash-window recovery path for "Stripe created the
Session but we died before storing its ID".

**Friends is in V1 after all** — the owner asked for it with the real
catalog, and it shares the enrolment machinery rather than duplicating it, so
it cost far less than the ~200 lines its deferral estimated. It adds the one
place an amount legitimately arrives from a browser: a member choosing what
to give monthly. That is not a price being trusted (a price says what a thing
costs and must come from the catalog); it is a person's decision, parsed to
exact cents server-side and bounded.

Known UX gap for M7: a member with a pending order who submits a *different*
valid choice is resumed to their existing checkout rather than told about it.
The schema permits one pending order per programme, so nothing is lost — but
the silence should become a sentence.

Gate passed: the owner paid a $75/month tier plus a $100 device with a test
card on Stripe's hosted page and was returned to the portal, which granted
nothing — settlement is M6's business. Both giving paths were walked against
the real sandbox too.

**M5 and M6 are one deployable unit.** Between them, money moves and nothing
records it. Fine as a milestone boundary; unacceptable as a deployed state.
Nothing built in M5 reaches a live Stripe account until M6's gate passes.

### M6 — money in, durably

Webhook inbox → canonical re-retrieval → projection. 17 event types, card only.
`payment_intent.succeeded` and `invoice.paid` are the only settlement
authorities; the checkout return page grants nothing.

This is also **the worker's milestone**, because "the order settles by itself"
is the worker doing its job. Its gate grows two clauses: a failed job visibly
retries with backoff, and a permanently failing job lands in `staff_alerts`
where a staff page shows it. A dead-letter queue nobody watches is not a
control, and the schema's decision to defer the reconciliation sweeper leans
on this queue being watched.

Two settlement designs land with this milestone's migration, both found by
review of M5:

- **A custom Friends subscription has no catalog price version to anchor**
  (the member set the amount), yet `memberships.tier_price_version_id` is
  `NOT NULL`. Migration 000004 adds a source-order-line reference and relaxes
  that column to null *only* for the custom-Friends case, with CHECK
  constraints making every other null combination impossible. The immutable
  order line is the anchor — a synthesized "current custom price" catalog item
  would collide with the catalog's single-open-version invariant the moment
  two members chose different amounts.
- **Nothing releases an inventory reservation.** The schema anticipated this
  (a four-state enum and a partial index on `expires_at WHERE state = 'held'`,
  both unread by any code) but the roadmap never named it, which is why it is
  named here now. The member path already abandons its own stale order; the
  worker sweep is this milestone's, against that index. Until it exists, every
  abandoned device enrolment permanently consumes stock.

Design to settle before M6's migration (batched as one): the webhook inbox
needs the same lease columns `outbox_jobs` already has (a worker that dies
mid-flight must not strand a paid order), `FOR UPDATE SKIP LOCKED` becomes the
single claim pattern, the `observed_at` semantics for the out-of-order guard
get pinned to canonical-retrieval time and tested with shuffled delivery, and
`webhook_events.payload` gets a retention window — it is the one place raw
PII would otherwise sit in the clear forever.

### M7 — staff can fulfill

Launch candidate. The launch sentence must pass end to end. `bootstrap-staff`
is part of this gate: granting the first administrator on a fresh database is
a step the launch sentence silently depends on.

### M8 — deploy, rotation, privacy

Compose plus Caddy, `rotate-pii`, the retention sweeper, subject-access export,
a lean `doctor`, and about 400 lines of documentation replacing 7,583.

Production domains, decided by the owner: the portal is
**`donate.triplebit.org`** (`PORTAL_BASE_URL`) and Pocket ID is
**`id.triplebit.org`** (`PORTAL_OIDC_ISSUER`). Sibling subdomains of one
registrable domain, which is exactly the situation the `__Host-` cookie
prefix defends: neither host can plant cookies on the other.

Proposed additional gate, pending owner sign-off: **restore, not just backup.**
The database is the sole source of truth for access and holds field-encrypted
PII whose keys live in the process environment of one VPS; a restore without
the matching keyring silently loses every ciphertext. The gate: restore onto a
different machine, with the keyring, proven by a member signing in and reading
their own settled order. Until that has happened once, the recovery posture is
unknown.

The rotation design was settled before M5's first ciphertext write (migration
000003): every ciphertext column holds the cryptox text envelope, whose
embedded key id is the *only* copy of that fact — a key-id column would be
the duplicated-fact bug that broke sessions, wearing a new hat. `rotate-pii`
selects stale rows through partial expression indexes on
`split_part(ciphertext, '.', 2)`, and needs no cursor: re-sealing a row
removes it from the predicate, so the query is its own resumable cursor.

### M9 — tax acknowledgments

Deliberately last, because acknowledgments are a downstream projection of
settled financial state and cannot be tested until M6 populates `donations` and
`refunds`. The hard part is the correction chain: a refund must produce a new
immutable revision, and the schema enforces
`contribution_amount + total_refunded = original_contribution_amount`.

Waiting costs nothing and buys two things. Donations that settle before this
ships can be issued retroactively, because every input — amount, date, donor,
fair-market-value snapshot, refund total — is frozen immutably in `order_lines`
and `donations`. And since V1 defers gifts, the first version handles only the
"no goods or services were provided" case, so gifts add one term later instead
of being debugged simultaneously.

Move this earlier, to just after M6, if receipts must go out on day one.

## Scope: what V1 does not build

Each is a route or a package, not a principle.

| Deferred | Why |
|---|---|
| Gifts, fair market value, thresholds | Largest source of validation branching |
| ACH, bank setup, mandates | ~800 lines across five packages; card-only V1 |
| Tier-change schedules | The Stripe Customer Portal does this |
| Stripe Entitlements | A second remote source of truth for access |
| Pocket ID group sync | A push into the IdP that nothing in V1 reads back |
| Guest-donation *claim* | Guest donation itself ships; the claim link does not |
| Donor tags, notes, search, CSV export | `audit_events` is still written, just not browsed |
| Device-replacement requirements | Re-enrolment policy; nobody has cancelled yet |
| Nine-permission matrix | Two roles: `admin`, `fulfillment` |
| Full Stripe re-observation sweeper | ~1,200 lines defending against an undelivered event |
| Outbound email, entirely | V1 sends nothing: acknowledgments render in the portal, staff watch a queue page. When mail lands it is its own package with its own layer number — the layering tool's motivating anecdote is a persistence package that imported SMTP |

This table, not the schema's `deferred past V1` comments, is the source of
truth for V1 scope. The SQL comments are frozen inside migration 000001 and
already disagree with the plan in two places (`acknowledgments` is deferred
there but M9 is planned; `guest_donors` is deferred there but guest donations
ship). When the M6 migration lands, the scope list moves into a Go file the
build can actually check, and the SQL comments become pointers.

**Cannot be cut**, because each is money- or access-correctness: webhook
idempotency and the out-of-order guard; retrieve-canonical-before-project;
inventory reservation; server-side price resolution; frozen order lines;
per-context Stripe uniqueness; CSRF on every mutating route; field-bound PII
encryption; revocable sessions; audit writes; Serializable with retry.

## Decisions worth remembering

The reasoning behind each lives in `docs/DECISIONS.md`; this table is the index.

| | Decision |
|---|---|
| D1 | Adopt `stripe-go` v86. It has zero runtime dependencies, and its webhook verification and expandable-ID handling delete ~2,500 lines of hand-rolled code |
| D2 | Migrations are append-only, per-file checksummed, and applied under an advisory lock; an applied file never changes. (Originally "one migration, frozen" — 000002 showed growth happens by appending, never by editing) |
| D3 | One CSRF token per session; no path binding |
| D4 | One source of truth per fact — the shape of the session fix |
| D5 | Guest donations ship; the claim flow defers |
| D6 | Access is a pure function of local state, not Stripe Entitlements |
| D7 | One binary with subcommands, not three |
| D8 | A mutating route cannot be registered without CSRF; handlers are not `http.HandlerFunc`, so there is no type-compatible way around the registrar |

## Open questions

- **Two Stripe accounts mean two Billing Portals.** `bpc_` configurations are
  account-specific, so there is no single "manage my billing" page once Friends
  ships.
- **Cross-account Customer Sharing: proven, with numbers.** The first spike
  (2026-07-30) found no propagation at all — the Organization had no sharing
  group; a Dashboard setting, invisible to the API, that would otherwise have
  been discovered mid-M5. The owner enabled customer and payment-method
  sharing; the re-run measured: Customers visible in the sibling account with
  the **same `cus_` ID in ~1.1s** (3 trials, both directions, attributes
  intact); a card attached in one account listable from the other with the
  **same `pm_` ID in ~7.6s**. M5's `EnsureCustomer` therefore looks the
  Customer up in either account and treats `resource_missing` as propagation
  lag with a bounded retry (spec: tolerate 60s; observed: seconds). The M5
  sandbox test asserts this end to end. Two Billing Portals (`bpc_` configs
  are account-specific) remains true and unresolved.
- **Card-only must stay enforced in code**, not as a Dashboard setting. Enabling
  ACH in the Stripe Dashboard would make four deferred event types load-bearing.

## Working on this

```sh
make db-up      # start a local PostgreSQL for tests
make check      # what CI runs, minus the database
make test-db    # what CI runs, including the database
make db-down
```

`make check` skips database tests when `PORTAL_TEST_DATABASE_URL` is unset,
which is right for a fast local loop. CI sets `PORTAL_REQUIRE_DB_TESTS=1`, which
turns that skip into a failure. A database test that can silently skip in CI is
not a test.
