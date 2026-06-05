FROM qos-local/common AS build
ARG APPLICATION_PACKAGE
ARG APPLICATION_BIN
WORKDIR /qos
ENV TARGET=
ENV RUSTFLAGS=
ENV CARGOFLAGS=
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY src ./src
RUN cargo build --locked --release -p ${APPLICATION_PACKAGE} --bin ${APPLICATION_BIN}
RUN mkdir -p /out && cp /qos/target/release/${APPLICATION_BIN} /out/app

FROM qos-local/common
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
