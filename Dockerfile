# ── Stage 1: Build ──
FROM rustlang/rust:nightly-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p talus-process-monitor

# ── Stage 2: Runtime ──
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create talus user and config directory for license
RUN groupadd -r talus && useradd -r -g talus -m -s /bin/false talus
RUN mkdir -p /etc/talus && chown talus:talus /etc/talus && chmod 700 /etc/talus

COPY --from=builder /src/target/release/talus-monitor /usr/local/bin/
RUN chmod +x /usr/local/bin/talus-monitor

# License file mount point (optional)
# Mount your license.dat to /etc/talus/license.dat
# VOLUME ["/etc/talus"]

# Health check: verify the binary runs
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD talus-monitor --version || exit 1

EXPOSE 0
ENTRYPOINT ["talus-monitor"]
