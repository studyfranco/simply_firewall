# Build stage
FROM rust:slim as builder

WORKDIR /app

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY static static

RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y build-essential ca-certificates pkg-config libssl-dev git --no-install-recommends \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/*

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM ghcr.io/studyfranco/docker-baseimages-debian:testing

RUN set -x \
    && apt update \
    && apt dist-upgrade -y \
    && apt autopurge -yy \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/*

# Install required certificates for TLS
RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y ca-certificates libsqlite3-0 --no-install-recommends \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/* \ 
    && mkdir /app

WORKDIR /app

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
