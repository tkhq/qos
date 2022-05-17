FROM rust:1.60 as builder
COPY ./ ./
RUN cargo build --bin qos-core --features vm --no-default-features --release

# We don't need the Rust toolchain to run the binary!
FROM debian:buster-slim AS runtime
WORKDIR app
COPY --from=builder /target/release/qos-core /usr/local/bin
ENTRYPOINT ["/usr/local/bin/qos-core", "--port", "6969", "--cid", "16"]