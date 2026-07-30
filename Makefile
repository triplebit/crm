GO ?= go

# Tests that need PostgreSQL read PORTAL_TEST_DATABASE_URL. They skip when it is
# unset, which is right for a quick local loop and wrong for CI — so CI sets
# PORTAL_REQUIRE_DB_TESTS=1, which turns that skip into a failure. Run
# `make db-up` to get a database locally; `make test-db` fails rather than skips.
TEST_DB_PORT ?= 55432
TEST_DB_URL  ?= postgres://portal:portal@127.0.0.1:$(TEST_DB_PORT)/portal_test?sslmode=disable

# CI runs no gate that is not a target in this file — every gating step in
# ci.yml is `make <target>` — so the local check and the merge gate cannot
# drift apart. (The reverse does not hold: db-up, clean and friends are local
# conveniences.)
.PHONY: all check build test test-db vet fmt fmt-check generate generate-check \
        layercheck lint-cookie mod-verify vuln compose-check docker-build \
        docker-check outdated db-up db-down clean

all: check

# check is what a pre-push hook should run: every offline gate, in the order
# that fails fastest. CI runs these plus test-db, vuln and compose-check,
# which need a database, the network and docker respectively.
check: fmt-check generate-check vet layercheck lint-cookie mod-verify build test

build:
	$(GO) build -o bin/portal ./cmd/portal

test:
	$(GO) test -race -count=1 ./...

# What CI runs: database tests must run, not skip.
test-db:
	PORTAL_TEST_DATABASE_URL="$(TEST_DB_URL)" PORTAL_REQUIRE_DB_TESTS=1 \
		$(GO) test -race -count=1 ./...

db-up:
	docker rm -f triplebit-pg >/dev/null 2>&1 || true
	docker run -d --name triplebit-pg \
		-e POSTGRES_USER=portal -e POSTGRES_PASSWORD=portal -e POSTGRES_DB=portal_test \
		-p $(TEST_DB_PORT):5432 postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 >/dev/null # 18.4-alpine
	@until docker exec triplebit-pg pg_isready -U portal -d portal_test >/dev/null 2>&1; do sleep 1; done
	@echo "test database ready: $(TEST_DB_URL)"

db-down:
	docker rm -f triplebit-pg >/dev/null 2>&1 || true

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi

# templ is pinned as a tool dependency in go.mod, so the generator and the
# runtime library can never drift. The previous implementation generated with
# templ v0.3.960 while go.mod required v0.3.1020, and then documented "do not
# commit the regenerated churn" as a workaround for its own build system.
generate:
	$(GO) tool templ generate

generate-check: generate
	@git diff --exit-code -- '*_templ.go' \
		|| { echo "generated templates are stale; run 'make generate' and commit the result"; exit 1; }

layercheck:
	$(GO) run ./internal/tools/layercheck

# internal/cookie is the only package permitted to construct a Set-Cookie
# header. Centralising it is what makes a __Host- prefixed cookie with a
# non-root path unrepresentable, rather than a mistake waiting to be repeated.
# Case-insensitive, covers .templ as well as .go, and searches every root that
# holds code (Header().Set canonicalises "set-cookie", so casing is not a
# boundary). grep's own errors — a renamed root, an unreadable file — land in
# the match list via 2>&1 and fail the target, instead of an empty search
# passing as a clean one. CI additionally proves this target can fail, by
# planting a known-bad probe and requiring a non-zero exit.
lint-cookie:
	@matches=$$(grep -rni --include='*.go' --include='*.templ' \
		-e 'http\.SetCookie' -e 'http\.Cookie' -e '"__Host-' -e '"Set-Cookie"' \
		internal cmd web migrations 2>&1 | grep -v '^internal/cookie/' || true); \
	if [ -n "$$matches" ]; then \
		echo "$$matches"; echo; echo "cookies must be written through internal/cookie only"; exit 1; \
	fi

# The module graph must be verifiable and tidy: go.sum mismatches and
# untracked dependency edits both fail, which matters more once stripe-go
# lands than it does today.
mod-verify:
	$(GO) mod verify
	$(GO) mod tidy -diff

# A merge gate, not an advisory sidecar. Pinned to a version, like everything
# else that runs in CI; update it deliberately.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

# The placeholder environment every compose gate runs with, defined once.
#
# It used to be written out four times, and the fourth copy went stale the
# moment a variable was added: CI failed because docker-check kept its own list
# and did not know about the webhook secrets. A gate's env list is not
# interesting enough to maintain in parallel.
COMPOSE_CHECK_ENV = \
	PORTAL_SESSION_KEY=check PORTAL_SESSION_KEY_ID=check \
	PORTAL_ENCRYPTION_KEY=check PORTAL_ENCRYPTION_KEY_ID=check \
	PORTAL_OIDC_CLIENT_ID=check PORTAL_OIDC_CLIENT_SECRET=check \
	PORTAL_STRIPE_SECRET_KEY=check \
	PORTAL_STRIPE_MEMBERSHIPS_ACCOUNT=check \
	PORTAL_STRIPE_DONATIONS_ACCOUNT=check \
	PORTAL_STRIPE_MEMBERSHIPS_WEBHOOK_SECRET=check \
	PORTAL_STRIPE_DONATIONS_WEBHOOK_SECRET=check \
	POCKET_ID_ENCRYPTION_KEY=checkcheckcheck

# The same list with PORTAL_SESSION_KEY absent, for the negative case below.
COMPOSE_CHECK_ENV_NO_SESSION_KEY = \
	PORTAL_SESSION_KEY_ID=check \
	PORTAL_ENCRYPTION_KEY=check PORTAL_ENCRYPTION_KEY_ID=check \
	PORTAL_OIDC_CLIENT_ID=check PORTAL_OIDC_CLIENT_SECRET=check \
	PORTAL_STRIPE_SECRET_KEY=check \
	PORTAL_STRIPE_MEMBERSHIPS_ACCOUNT=check \
	PORTAL_STRIPE_DONATIONS_ACCOUNT=check \
	PORTAL_STRIPE_MEMBERSHIPS_WEBHOOK_SECRET=check \
	PORTAL_STRIPE_DONATIONS_WEBHOOK_SECRET=check \
	POCKET_ID_ENCRYPTION_KEY=checkcheckcheck

# Validates compose.yaml without starting anything. The dummy values satisfy
# the ":?" required-variable checks, whose job is refusing a real start-up
# without real keys — syntax validation is not a start-up.
#
# --env-file /dev/null makes the gate hermetic. Compose reads .env from the
# project directory by default, so without this the check validated the
# developer's local secrets rather than the file under test — and the
# negative case below silently passed for the wrong reason, which is how it
# was noticed.
compose-check:
	$(COMPOSE_CHECK_ENV) \
	docker compose --env-file /dev/null config -q
	@# And prove the required-variable guards are guards: with one unset,
	@# compose must refuse. Otherwise a weakened ":?" that silently defaulted
	@# would produce identical valid output to a correct one.
	@if $(COMPOSE_CHECK_ENV_NO_SESSION_KEY) \
		docker compose --env-file /dev/null config -q 2>/dev/null; then \
		echo "compose accepted a missing PORTAL_SESSION_KEY; the required-variable guard is not a guard"; \
		exit 1; \
	fi
	@# D7, checked rather than promised: the worker container must never be
	@# handed the session or PII keys. It cannot use them — RequireWorker has
	@# an AST test forbidding it from naming them — but a secret present in a
	@# compromised container's environment is exposed whether the process reads
	@# it or not. The worker block was written by copying the portal block,
	@# which is exactly how a key gets carried along by accident.
	@if $(COMPOSE_CHECK_ENV) \
		docker compose --env-file /dev/null config \
		| awk '/^  worker:/{inside=1; next} /^  [a-z]/{inside=0} inside' \
		| grep -E 'PORTAL_(SESSION_KEY|ENCRYPTION_KEY|OIDC)'; then \
		echo "the worker service is configured with session, PII or OIDC secrets it must never hold (D7)"; \
		exit 1; \
	fi

# Builds the container image with the revision stamped in, since the build
# context deliberately excludes .git. A build from a modified worktree is
# stamped <sha>-dirty: an image claiming a clean commit whose bytes are not
# that commit is worse than one admitting it.
docker-build:
	@rev=$$(git rev-parse HEAD); \
	if ! git diff --quiet HEAD; then rev="$$rev-dirty"; fi; \
	echo "building portal image at $$rev"; \
	PORTAL_REVISION=$$rev docker compose build

# The CI gate for the container. It builds THROUGH compose, not with a raw
# docker build: compose is what production uses, and it is where the build
# context and the PORTAL_REVISION build arg are wired. A raw build would prove
# the Dockerfile compiles while leaving a broken compose build stanza to
# surface at deploy time.
docker-check:
	PORTAL_REVISION=ci-check \
	$(COMPOSE_CHECK_ENV) \
	docker compose --env-file /dev/null build --quiet

# Reports what has moved on upstream. Deliberately a report and not a gate:
# it depends on network calls to third-party registries, and a merge gate that
# fails because someone else published a release is a gate that teaches people
# to ignore gates.
#
# It exists because pinning is not the same as pinning to something current.
# This project once ran Pocket ID 1.16.0 for weeks under an innocent-looking
# `:v1` tag while 2.12.0 was out — a stale pin reads as a deliberate one, which
# is worse than no pin at all. Run this before any release, and when adding a
# dependency.
outdated:
	@echo "== Go modules with newer versions =="
	@# The lookup's exit status is preserved: piping it into grep would turn an
	@# unreachable proxy into a cheerful "all current", which is the same
	@# masking bug this file already fixed once in lint-cookie.
	@out=$$($(GO) list -m -u -f '{{if .Update}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all) \
		|| { echo "  module lookup FAILED; currency is unknown"; exit 1; }; \
	if [ -n "$$(echo "$$out" | tr -d '[:space:]')" ]; then echo "$$out" | grep . ; \
	else echo "  all current"; fi
	@echo
	@echo "== pinned images: verify these by hand against the sources below =="
	@# Deliberately NOT a drift check. It lists what is pinned; comparing that
	@# to upstream needs a query per registry, and a Makefile that half-does it
	@# would be the kind of tool that looks like a control and is not.
	@# The tag comment sits on the same line in compose/ci and on the line
	@# above in a Dockerfile, because # is not a comment inside FROM. Both are
	@# reported: an image this misses is an image nobody rechecks, which is the
	@# exact failure this target exists for.
	@grep -rh -B1 '@sha256:' Dockerfile compose.yaml .github/workflows/ci.yml \
		| grep -oE '#[[:space:]]*[a-z0-9][a-z0-9./:-]*$$' \
		| sed -E 's/#[[:space:]]*//' | sort -u | sed 's/^/  /'
	@echo
	@echo "  authoritative sources:"
	@echo "    pocket-id   https://github.com/pocket-id/pocket-id/releases/latest"
	@echo "    postgres    https://hub.docker.com/_/postgres/tags?name=alpine"
	@echo "    golang      https://hub.docker.com/_/golang/tags?name=alpine"
	@echo "    distroless  https://github.com/GoogleContainerTools/distroless"
	@echo "    actions     gh api repos/actions/<name>/releases/latest --jq .tag_name"

clean:
	rm -rf bin
