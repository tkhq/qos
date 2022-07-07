FROM rust:bullseye as builder
COPY ./ ./
RUN cargo build --manifest-path ./qos-host/Cargo.toml --bin qos-host --features vm --no-default-features

FROM debian:bullseye-slim AS runtime
WORKDIR app
RUN apt-get update \
  && apt-get install -y libssl-dev
  
COPY --from=builder /target/debug/qos-host /usr/local/bin
ENTRYPOINT ["/usr/local/bin/qos-host"]
