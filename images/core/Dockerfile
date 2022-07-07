FROM rust:bullseye as builder
COPY ./ ./
RUN cargo build --manifest-path ./qos-core/Cargo.toml --bin qos-core --features vm --no-default-features

# We don't need the Rust toolchain to run the binary!
FROM debian:bullseye-slim AS runtime
WORKDIR app
RUN apt-get update \
  && apt-get install -y libssl-dev
COPY --from=builder /target/debug/qos-core /usr/local/bin
ENTRYPOINT ["/usr/local/bin/qos-core", "--port", "6969", "--cid", "16"]