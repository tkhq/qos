FROM scratch
LABEL org.opencontainers.image.source=https://github.com/tkhq/qos
ARG BIN
COPY ${BIN} /qos_host
ENTRYPOINT ["/qos_host"]
