# Build stage. CGO off: the binary must run in a distroless image with no libc.
# Images are digest-pinned like everything else that executes in this project;
# the tag each digest resolved from is named in the comment above it, because
# a # is not a comment inside a FROM line.
# golang:1.26-alpine
FROM golang@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /portal ./cmd/portal

# Runtime stage. Distroless static: no shell, no package manager, no root.
# The healthcheck is the portal binary probing itself, because there is no
# curl in here and there should not be.
# gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /portal /portal
ENTRYPOINT ["/portal"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["/portal", "healthcheck"]
