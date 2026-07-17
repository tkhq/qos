# syntax=docker/dockerfile:1
FROM common AS base
ADD . /src

FROM base AS build
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/.cargo <<-EOF
	set -eux
	cd /src && cargo build ${CARGOFLAGS} -p qos_bridge --bin ingress --features egress,qemu
	cd /src && cargo build ${CARGOFLAGS} -p qos_bridge --bin egress --features egress,qemu
	cp /src/target/${TARGET}/release/ingress /qos_bridge
	cp /src/target/${TARGET}/release/egress /qos_egress
	file /qos_bridge | grep "static-pie"
	file /qos_egress | grep "static-pie"
EOF

FROM base AS install
WORKDIR /rootfs
COPY --from=build /qos_bridge .
COPY --from=build /qos_egress .
RUN find . -exec touch -hcd "@0" "{}" +

FROM scratch AS package
COPY --from=install /rootfs .
ENTRYPOINT ["/qos_bridge"]
