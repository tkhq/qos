#!/bin/sh

IMAGES=(rust bash coreutils findutils grep musl libunwind openssl zlib ca-certificates binutils pkgconf git gen_initramfs eif_build llvm pcsc-lite file gcc linux-nitro)

for image in "${IMAGES[@]}"
do
  docker image pull stagex/${image}
  docker image tag stagex/${image} ghcr.io/tkhq/stagex/${image}
  docker image push ghcr.io/tkhq/stagex/${image}
done