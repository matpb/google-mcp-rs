# rust:1.94-alpine
FROM rust@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS builder
WORKDIR /build
RUN apk upgrade --no-cache && apk add --no-cache musl-dev

# Cache dependencies — copy manifest first
COPY Cargo.toml Cargo.lock* ./

# Create dummy source to build deps
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --locked 2>/dev/null || true && \
    rm -rf src/

# Copy real source and build
COPY src/ src/
RUN touch src/main.rs && \
    cargo build --release --locked && \
    mkdir /data

# gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
LABEL org.opencontainers.image.source="https://github.com/matpb/google-mcp-rs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Multi-tenant Rust MCP server for Google Workspace"
COPY --from=builder /build/target/release/google-mcp /usr/local/bin/
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8433
ENTRYPOINT ["google-mcp"]
