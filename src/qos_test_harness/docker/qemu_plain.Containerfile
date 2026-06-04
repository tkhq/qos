FROM qos-local/common AS build

COPY . /src
WORKDIR /src

RUN cargo build ${CARGOFLAGS} -p qos_core --features mock --bin qos_core
RUN cargo build ${CARGOFLAGS} -p qos_test_harness --bin light_init
RUN cargo build ${CARGOFLAGS} -p qos_test_harness --bin signed_echo

RUN mkdir -p /package
RUN cp target/${TARGET}/release/qos_core /package/qos_core
RUN cp target/${TARGET}/release/light_init /package/init
RUN cp target/${TARGET}/release/signed_echo /package/signed_echo
RUN find /package -exec touch -hcd "@0" "{}" +

FROM scratch AS package
COPY --from=build /package/ /
