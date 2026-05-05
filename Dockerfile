FROM rust:1.94-alpine AS builder
WORKDIR /build
RUN apk upgrade --no-cache && apk add --no-cache musl-dev

# Cache dependencies — copy manifest first
COPY Cargo.toml Cargo.lock* ./

# Create dummy source to build deps
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src/

# Copy real source and build
COPY src/ src/
RUN touch src/main.rs && \
    cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/google-mcp /usr/local/bin/
EXPOSE 8433
ENTRYPOINT ["google-mcp"]
