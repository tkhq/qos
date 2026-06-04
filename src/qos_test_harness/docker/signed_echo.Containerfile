FROM qos-local/common AS build
WORKDIR /qos
ENV TARGET=
ENV RUSTFLAGS=
ENV CARGOFLAGS=
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY src ./src
RUN cargo build --locked --release -p qos_test_harness --bin signed_echo

FROM qos-local/common
COPY --from=build /qos/target/release/signed_echo /usr/local/bin/signed_echo
ENTRYPOINT ["/usr/local/bin/signed_echo"]
