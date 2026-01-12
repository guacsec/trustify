# Build stage
FROM rust:1.83-alpine AS builder

# Install musl-dev for static linking
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual binary (touch to update mtime so cargo rebuilds)
RUN touch src/main.rs && cargo build --release

# Runtime stage - use minimal distroless image
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the binary from builder
COPY --from=builder /app/target/release/trustify /usr/local/bin/trustify

# Set the entrypoint
ENTRYPOINT ["trustify"]
