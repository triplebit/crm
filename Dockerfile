# Build stage. CGO off: the binary must run in a distroless image with no libc.
# Images are digest-pinned like everything else that executes in this project;
# the tag each digest resolved from is named in the comment above it, because
# a # is not a comment inside a FROM line.
# golang:1.26.5-alpine
FROM golang@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# .git is dockerignored (it would bust the cache every commit), so the VCS
# stamp go build normally embeds is absent here. The revision arrives as a
# build arg instead; compose and the make target pass it. An image that
# cannot say which commit it is fails exactly when that matters.
ARG PORTAL_REVISION=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.injectedRevision=${PORTAL_REVISION}" \
    -o /portal ./cmd/portal

# Runtime stage. Distroless static: no shell, no package manager, no root.
# The healthcheck is the portal binary probing itself, because there is no
# curl in here and there should not be.
# gcr.io/distroless/static-debian13:nonroot
FROM gcr.io/distroless/static-debian13@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
COPY --from=build /portal /portal
ENTRYPOINT ["/portal"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["/portal", "healthcheck"]
