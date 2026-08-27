#!/usr/bin/env bash
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fixture="$root/src/integration/fixtures/stagex-rootless-buildkit"
artifacts="$root/target/qemu-stagex-buildkit-e2e"
oci="$artifacts/stagex.oci.tar"
log="$artifacts/qemu.log"

mkdir -p "$artifacts"

docker buildx build \
	--platform linux/amd64 \
	--provenance=false \
	--sbom=false \
	--file "$fixture/Containerfile" \
	--output "type=oci,dest=$oci,compression=gzip" \
	"$fixture"

tar -xOf "$oci" index.json \
	| jq -er '.manifests | map(select(.platform.architecture == "amd64" and .platform.os == "linux")) | first.digest' \
	> "$artifacts/stagex.digest"

docker buildx build \
	--platform linux/amd64 \
	--file "$root/src/images/qos_stagex_qemu_e2e/Containerfile" \
	--build-context "stagex=$artifacts" \
	--output "type=local,dest=$artifacts/image" \
	"$root"

set +e
timeout 300 qemu-system-x86_64 \
	-machine microvm \
	-cpu max \
	-m 4096 \
	-smp 4 \
	-nodefaults \
	-no-reboot \
	-display none \
	-serial stdio \
	-kernel "$artifacts/image/bzImage" \
	-initrd "$artifacts/image/rootfs.cpio" \
	-append "reboot=k root=/dev/ram0 panic=1 nomodules console=ttyS0" \
	2>&1 | tee "$log"
qemu_status=${PIPESTATUS[0]}
set -e

if ! grep -q "QOS_STAGEX_PACKAGE_BUILT_OK" "$log"; then
	echo "StageX package build marker was not observed (QEMU status $qemu_status)" >&2
	exit 1
fi
if ! grep -q "QOS_STAGEX_BUILDKIT_E2E_OK" "$log"; then
	echo "QOS QEMU e2e completion marker was not observed (QEMU status $qemu_status)" >&2
	exit 1
fi
