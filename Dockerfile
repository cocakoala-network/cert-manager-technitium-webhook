# Stage 1: Download dependencies
FROM golang:1.24-alpine AS deps

RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

# Stage 2: Build the binary
FROM deps AS build

COPY . .

# Run tests during build to catch issues early
RUN CGO_ENABLED=0 go test -v ./...

# Build a statically linked binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -trimpath \
    -o /webhook .

# Stage 3: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/cocakoala-network/cert-manager-technitium-webhook"
LABEL org.opencontainers.image.description="cert-manager DNS01 webhook solver for Technitium DNS Server"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /webhook /usr/local/bin/webhook

USER nonroot:nonroot

ENTRYPOINT ["webhook"]
