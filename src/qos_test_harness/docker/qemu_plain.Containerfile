FROM qos-local/common AS build

ARG APPLICATION_PACKAGE
ARG APPLICATION_BIN
COPY . /src
WORKDIR /src

RUN cargo build ${CARGOFLAGS} -p qos_core --features mock --bin qos_core
RUN cargo build ${CARGOFLAGS} -p qos_test_harness --bin light_init
RUN cargo build ${CARGOFLAGS} -p ${APPLICATION_PACKAGE} --bin ${APPLICATION_BIN}

RUN mkdir -p /package
RUN cp target/${TARGET}/release/qos_core /package/qos_core
RUN cp target/${TARGET}/release/light_init /package/init
RUN cp target/${TARGET}/release/${APPLICATION_BIN} /package/${APPLICATION_BIN}
RUN find /package -exec touch -hcd "@0" "{}" +

FROM scratch AS package
COPY --from=build /package/ /
