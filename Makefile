GO ?= go

# Tests that need PostgreSQL read PORTAL_TEST_DATABASE_URL. They skip when it is
# unset, which is right for a quick local loop and wrong for CI — so CI sets
# PORTAL_REQUIRE_DB_TESTS=1, which turns that skip into a failure. Run
# `make db-up` to get a database locally; `make test-db` fails rather than skips.
TEST_DB_PORT ?= 55432
TEST_DB_URL  ?= postgres://portal:portal@127.0.0.1:$(TEST_DB_PORT)/portal_test?sslmode=disable

# Every target here also runs in CI, and CI runs no target that is not here.
# When the two drift, the local check stops meaning anything.
.PHONY: all check build test test-db vet fmt fmt-check generate generate-check \
        layercheck lint-cookie db-up db-down clean

all: check

# check is what a pre-push hook should run: everything CI gates on, in the order
# that fails fastest.
check: fmt-check generate-check vet layercheck lint-cookie build test

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
lint-cookie:
	@if grep -rn --include='*.go' -e 'http.SetCookie' -e '&http.Cookie{' -e '"__Host-' -e '"Set-Cookie"' \
		internal cmd 2>/dev/null | grep -v '^internal/cookie/'; then \
		echo; echo "cookies must be written through internal/cookie only"; exit 1; \
	fi

clean:
	rm -rf bin
