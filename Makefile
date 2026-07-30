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
        layercheck lint-cookie mod-verify vuln compose-check db-up db-down clean

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
		-p $(TEST_DB_PORT):5432 postgres:17-alpine >/dev/null
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
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

# Validates compose.yaml without starting anything. The dummy values satisfy
# the ":?" required-variable checks, whose job is refusing a real start-up
# without real keys — syntax validation is not a start-up.
compose-check:
	PORTAL_SESSION_KEY=check PORTAL_SESSION_KEY_ID=check \
	PORTAL_ENCRYPTION_KEY=check PORTAL_ENCRYPTION_KEY_ID=check \
	PORTAL_OIDC_CLIENT_ID=check PORTAL_OIDC_CLIENT_SECRET=check \
	docker compose config -q

clean:
	rm -rf bin
