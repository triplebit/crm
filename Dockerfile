# Build stage. CGO off: the binary must run in a distroless image with no libc.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /portal ./cmd/portal

# Runtime stage. Distroless static: no shell, no package manager, no root.
# The healthcheck is the portal binary probing itself, because there is no
# curl in here and there should not be.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /portal /portal
ENTRYPOINT ["/portal"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["/portal", "healthcheck"]
