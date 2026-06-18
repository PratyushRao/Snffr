# Multi-stage build for Rust Agent
FROM rust:1.85-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/snffr

# Copy proto files (needed by build.rs)
COPY proto ./proto

# Copy agent source code
COPY agent ./agent

# Build the agent
WORKDIR /usr/src/snffr/agent
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies: libpcap and iptables (for the response actions)
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /usr/src/snffr/agent/target/release/agent /usr/local/bin/snffr-agent

# Run the agent
CMD ["snffr-agent"]
