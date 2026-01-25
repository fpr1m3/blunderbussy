# Multi-stage build for MSF Bridge
FROM docker.io/library/golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy source code first (for go mod tidy to work)
COPY go.mod ./
COPY *.go ./

# Download and tidy dependencies
RUN go mod tidy && go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o msf-bridge .

# Final stage - minimal image
FROM docker.io/library/alpine:3.19

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN adduser -D -g '' appuser

# Copy binary from builder
COPY --from=builder /app/msf-bridge /app/msf-bridge

# Use non-root user
USER appuser

# Expose the bridge port
EXPOSE 9997

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9997/health || exit 1

# Run the bridge
ENTRYPOINT ["/app/msf-bridge"]
