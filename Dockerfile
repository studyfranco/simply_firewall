# Build stage
FROM rust:1.77-bookworm as builder

WORKDIR /app

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY migration migration
COPY static static

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install required certificates for TLS
RUN apt-get update && apt-get install -y ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/*

# Copy the binary and static files
COPY --from=builder /app/target/release/simply_firewall /usr/local/bin/simply_firewall
COPY static /app/static

# Expose API/Frontend port
EXPOSE 3000

# Default environment configuration
ENV DATABASE_URL=sqlite://data/firewall.db?mode=rwc
ENV RUST_LOG=info

# Define command
CMD ["simply_firewall"]
