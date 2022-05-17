FROM rust:1.60 as builder
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo build

COPY ./ ./
RUN cargo build --bin qos-core --features vm --no-default-features

# We don't need the Rust toolchain to run the binary!
FROM debian:buster-slim AS runtime
WORKDIR app
RUN apt-get update && apt-get install -y libssl-dev
COPY --from=builder /target/debug/qos-core /usr/local/bin
ENTRYPOINT ["/usr/local/bin/qos-core", "--port", "6969", "--cid", "16"]