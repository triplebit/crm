# Triplebit Portal — rebuild roadmap

Progress tracker for the rebuild. Every milestone ends in a command a human runs
whose output is the gate — never "wrote package X".

**Status: M2 in progress.**

| | Milestone | Gate | Status |
|---|---|---|---|
| M0 | Repo can prove itself | CI green on GitHub | ✅ done |
| M1 | Schema, migrations, `WithTx` | migrate twice; 40 tables; real 40001 retried | ✅ done |
| M2 | Leaf packages | their tests, plus layering clean | 🔨 in progress |
| M3 | A real member can sign in | sign in through Pocket ID, land on `/account` | ⬜ |
| M4 | The catalog is authoritative | `catalog-sync` against a Stripe sandbox | ⬜ |
| M5 | Money out | a real test card reaches Stripe Checkout | ⬜ |
| M6 | Money in, durably | the order settles by itself, replay-safe | ⬜ |
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

CI with no `continue-on-error`; `make check` runs exactly what CI runs;
`layercheck` makes the package layering a build failure; `internal/core` with
`AccountRef` and `Environment` as opaque types whose zero value panics.

### M1 — schema, migrations, transactions ✅

40 tables ported with four reviewed edits applied inline. Schema frozen at
`15376d94ce0636dceeebb7a3b0b1a866a1e782bcb6eaa013d74411e94850a4bb`.

1. `browser_sessions` redesigned so the login bug is unrepresentable.
2. `consents` gained `withdrawn_at`; consent is an authorization, not a log.
3. `users.passkey_prompt_dismissed_at` replaced a cookie browsers rejected.
4. An index for the out-of-order projection guard, which had none.

`internal/db` provides one `Conn` interface where there were six, and `WithTx`
makes serialization-failure retry a field rather than a project.

### M2 — leaf packages 🔨

Port `safeerr`, `cryptox`, `httpx`, `csrf`; add `cookie`, `tokens`, `money`,
`redact`. Two behaviour changes while porting:

- **`httpx` XFF fix.** One malformed `X-Forwarded-For` currently collapses every
  rate limit into a single global bucket, so 20 requests lock every user out of
  login and checkout for ten minutes.
- **`csrf` path binding dropped.** Binding tokens to `"METHOD /path"` forced
  three parallel hardcoded lists and a 200-line render function, and defends
  against a threat that requires the attacker to already hold the victim's
  token.

`cookie` is new and exists so that a `__Host-` prefixed cookie with a non-root
path cannot be written: no exported type in the package has a `Path` field.

### M3 — a real member can sign in

The milestone the previous implementation never reached. Also replaces its four
sequential per-request database round trips with one statement.

### M4 — the catalog is authoritative

The browser submits slugs and dollar strings only. The server resolves prices
from an allowlisted catalog snapshot and parses cents itself, with no float.

### M5 — money out

Order draft → inventory reservation → Stripe Checkout Session → attach →
redirect. Includes the crash-window recovery path for "Stripe created the
Session but we died before storing its ID".

### M6 — money in, durably

Webhook inbox → canonical re-retrieval → projection. 17 event types, card only.
`payment_intent.succeeded` and `invoice.paid` are the only settlement
authorities; the checkout return page grants nothing.

### M7 — staff can fulfill

Launch candidate. The launch sentence must pass end to end.

### M8 — deploy, rotation, privacy

Compose plus Caddy, `rotate-pii`, the retention sweeper, subject-access export,
a lean `doctor`, and about 400 lines of documentation replacing 7,583.

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
| Friends programme | Structurally identical to hotspot; ~200 lines later |
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

**Cannot be cut**, because each is money- or access-correctness: webhook
idempotency and the out-of-order guard; retrieve-canonical-before-project;
inventory reservation; server-side price resolution; frozen order lines;
per-context Stripe uniqueness; CSRF on every mutating route; field-bound PII
encryption; revocable sessions; audit writes; Serializable with retry.

## Decisions worth remembering

| | Decision |
|---|---|
| D1 | Adopt `stripe-go` v86. It has zero runtime dependencies, and its webhook verification and expandable-ID handling delete ~2,500 lines of hand-rolled code |
| D2 | One migration, all 40 tables, frozen after first apply |
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
- **Cross-account Customer Sharing is the highest-risk unproven integration.**
  M5's sandbox test must assert propagation within a bounded time.
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
