# Tag and digest together, so digest bumps stay on this tag.
FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS builder
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.source="https://github.com/matpb/google-mcp-rs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Multi-tenant Rust MCP server for Google Workspace"
COPY --from=builder /build/target/release/google-mcp /usr/local/bin/
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8433
ENTRYPOINT ["google-mcp"]
