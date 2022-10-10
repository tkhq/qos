FROM rust:bullseye as builder
COPY ./ ./
RUN cargo build --manifest-path ./qos_host/Cargo.toml --bin qos_host --features vm --no-default-features

FROM debian:bullseye-slim AS runtime
WORKDIR app
RUN apt-get update \
  && apt-get install -y libssl-dev

COPY --from=builder /target/debug/qos_host /usr/local/bin
ENTRYPOINT ["/usr/local/bin/qos_host"]
