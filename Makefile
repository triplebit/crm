GO ?= go

# Every target here also runs in CI, and CI runs no target that is not here.
# When the two drift, the local check stops meaning anything.
.PHONY: all check build test vet fmt fmt-check generate generate-check layercheck lint-cookie clean

all: check

# check is what a pre-push hook should run: everything CI gates on, in the order
# that fails fastest.
check: fmt-check generate-check vet layercheck lint-cookie build test

build:
	$(GO) build -o bin/portal ./cmd/portal

test:
	$(GO) test -race -count=1 ./...

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
	@if grep -rn --include='*.go' -e 'http.SetCookie' -e '&http.Cookie{' -e '"__Host-' \
		internal cmd 2>/dev/null | grep -v '^internal/cookie/'; then \
		echo; echo "cookies must be written through internal/cookie only"; exit 1; \
	fi

clean:
	rm -rf bin
