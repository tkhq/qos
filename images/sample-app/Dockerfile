FROM rust:bullseye as builder
COPY ./ ./
RUN cargo build --bin sample-app

# We don't need the Rust toolchain to run the binary!
FROM debian:bullseye-slim AS runtime
WORKDIR app
RUN apt-get update \
  && apt-get install -y libssl-dev
COPY --from=builder /target/debug/sample-app /usr/local/bin