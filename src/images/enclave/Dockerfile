FROM scratch
LABEL org.opencontainers.image.source=https://github.com/tkhq/qos
ARG BIN
ARG EIF
VOLUME /run/nitro_enclaves
VOLUME /var/log/run/nitro_enclaves
COPY ${BIN} /qos_enclave
COPY ${EIF} /nitro.eif
ENTRYPOINT ["/qos_enclave"]
ENV EIF_PATH=/nitro.eif
ENV ENCLAVE_NAME=qos
EXPOSE 8080
