ARG EIF_BUILD_IMAGE
ARG GEN_INITRAMFS_IMAGE
ARG LINUX_NITRO_IMAGE
ARG LIBUNWIND_IMAGE
ARG IPROUTE2_IMAGE
ARG MUSL_IMAGE
ARG RUST_BUILD_IMAGE
ARG TARGET=x86_64-unknown-linux-musl

FROM ${EIF_BUILD_IMAGE} AS eif_build
FROM ${GEN_INITRAMFS_IMAGE} AS gen_initramfs
FROM ${LINUX_NITRO_IMAGE} AS linux_nitro
FROM ${LIBUNWIND_IMAGE} AS libunwind
FROM ${IPROUTE2_IMAGE} AS iproute2
FROM ${MUSL_IMAGE} AS musl

FROM ${RUST_BUILD_IMAGE} AS build
ARG TARGET
ADD . /src/

ENV CARGOFLAGS="--target ${TARGET} --release"
ENV CARGO_HOME=/tmp/rust
ENV RUSTFLAGS='-C target-feature=+crt-static'

FROM build AS build_init
ARG TARGET
WORKDIR /src/src/init
RUN cargo build --features egress,qemu ${CARGOFLAGS}
RUN cp target/${TARGET}/release/init /
RUN file /init | grep "static-pie"

FROM build AS build_egress
ARG TARGET
ENV CARGOFLAGS="--locked --no-default-features --profile release-panic-abort --target ${TARGET}"
WORKDIR /src/src/qos_bridge
RUN cargo build --features egress,qemu ${CARGOFLAGS} --bin egress
RUN cp ../../target/${TARGET}/release-panic-abort/egress /egress
RUN file /egress | grep "static-pie"

FROM build AS build_eif
WORKDIR /build_cpio
COPY --from=eif_build . /
COPY --from=gen_initramfs . /
COPY --from=libunwind . /
COPY --from=build_init /init .
COPY --from=linux_nitro /nsm.ko .
COPY --from=iproute2 . /
COPY --from=musl . /
COPY --from=build_egress /egress .
COPY in/resolv.conf resolv.conf
COPY <<-EOF initramfs.list
	file /init     init    0700 0 0
	file /nsm.ko   nsm.ko  0600 0 0
	dir  /run              0755 0 0
	dir  /tmp              0755 0 0
	dir  /etc              0755 0 0
	dir  /bin              0755 0 0
	dir  /sbin             0755 0 0
	dir  /proc             0755 0 0
	dir  /sys              0755 0 0
	dir  /usr              0755 0 0
	dir  /lib              0755 0 0
	dir  /usr/bin          0755 0 0
	dir  /usr/sbin         0755 0 0
	dir  /usr/lib          0755 0 0
	dir  /dev              0755 0 0
	dir  /dev/shm          0755 0 0
	dir  /dev/pts          0755 0 0
	nod  /dev/console      0600 0 0 c 5 1
	file /egress   egress 0700 0 0
	file /usr/sbin/ip      /usr/sbin/ip     0700 0 0
	file /lib/ld-musl-x86  /usr/lib/ld-musl-x86_64.so.1                   0700 0 0
	file /etc/resolv.conf  resolv.conf      0644 0 0
EOF
ENV CPIO_TIMESTAMP=1
ENV KBUILD_BUILD_TIMESTAMP=1
RUN <<-EOF
	find . -exec touch -hcd "@0" "{}" +
	mkdir /build_eif
	gen_init_cpio -t 1 initramfs.list > /build_eif/rootfs.cpio
	touch -hcd "@0" /build_eif/rootfs.cpio
EOF
WORKDIR /build_eif
COPY --from=linux_nitro /bzImage .
COPY --from=linux_nitro /linux.config .
RUN eif_build \
	--ramdisk rootfs.cpio \
	--kernel bzImage \
	--kernel_config linux.config \
	--pcrs_output /nitro.pcrs \
	--output /nitro.eif \
	--cmdline "reboot=k initrd=0x2000000 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"

FROM scratch AS package
COPY --from=build_eif /nitro.eif .
COPY --from=build_eif /nitro.pcrs .
