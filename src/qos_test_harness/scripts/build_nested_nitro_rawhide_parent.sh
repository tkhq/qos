#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)

default_bundle_dir="${repo_root}/target/qos-test-harness/nested-nitro/rawhide-parent"
bundle_dir="${QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE:-${QOS_NESTED_NITRO_RAWHIDE_PARENT_DIR:-${default_bundle_dir}}}"
case "${bundle_dir}" in
	/*) ;;
	*) bundle_dir="${repo_root}/${bundle_dir}" ;;
esac

fedora_image="${QOS_NESTED_NITRO_RAWHIDE_IMAGE:-fedora:rawhide}"
platform="${QOS_NESTED_NITRO_RAWHIDE_PLATFORM:-linux/amd64}"
rootfs_size="${QOS_NESTED_NITRO_RAWHIDE_ROOTFS_SIZE:-2G}"
qemu_packages="${QOS_NESTED_NITRO_RAWHIDE_QEMU_PACKAGES:-qemu-system-x86-core}"

case "${bundle_dir}" in
	""|"/"|"/."|"/.."|"/usr"|"/usr/"*|"/bin"|"/bin/"*|"/lib"|"/lib/"*|"/lib64"|"/lib64/"*)
		echo "refusing unsafe parent bundle output path: ${bundle_dir}" >&2
		exit 2
		;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/qos-nested-rawhide-parent.XXXXXX")
cleanup() {
	rm -rf "${work_dir}"
}
trap cleanup EXIT

echo "Building Linux/x86_64 Rawhide nested Nitro parent bundle"
echo "  image:       ${fedora_image}"
echo "  platform:    ${platform}"
echo "  output:      ${bundle_dir}"
echo "  rootfs size: ${rootfs_size}"

docker run \
	--rm \
	--interactive \
	--platform "${platform}" \
	--volume "${work_dir}:/out" \
	--env "BASE_IMAGE=${fedora_image}" \
	--env "QEMU_PACKAGES=${qemu_packages}" \
	--env "ROOTFS_SIZE=${rootfs_size}" \
	"${fedora_image}" \
	/bin/bash -s <<'IN_CONTAINER'
set -euo pipefail

parent_root=/parent-root
rootfs_image=/out/rootfs.ext4

cat > /etc/dnf/dnf.conf <<'EOF'
[main]
install_weak_deps=False
keepcache=False
EOF

mkdir -p /etc/dracut.conf.d
cat > /etc/dracut.conf.d/qos-nested-parent.conf <<'EOF'
hostonly="no"
add_drivers+=" virtio_pci virtio_blk virtio_net virtio_console virtio_balloon virtio_rng 9p 9pnet 9pnet_virtio vsock vmw_vsock_virtio_transport vmw_vsock_virtio_transport_common "
EOF

# shellcheck disable=SC2086
dnf -y --setopt=install_weak_deps=False install \
	bash \
	coreutils \
	dracut \
	e2fsprogs \
	file \
	findutils \
	iproute \
	kernel-core \
	kernel-modules-core \
	kmod \
	procps-ng \
	tar \
	util-linux \
	${QEMU_PACKAGES} \
	vhost-device-vsock

kernel_version=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1 | xargs -n1 basename)
kernel_path="/lib/modules/${kernel_version}/vmlinuz"
initramfs_path="/out/initramfs.img"

if [ ! -f "${kernel_path}" ]; then
	echo "missing Rawhide kernel image at ${kernel_path}" >&2
	exit 1
fi

kernel_driver_is_module() {
	local module=$1
	find "/lib/modules/${kernel_version}" -name "${module}.ko*" | grep -q .
}

kernel_driver_is_builtin() {
	local module=$1
	[ -f "/lib/modules/${kernel_version}/modules.builtin" ] \
		&& grep -Eq "/${module}\\.ko$" "/lib/modules/${kernel_version}/modules.builtin"
}

kernel_driver_is_available() {
	local module=$1
	kernel_driver_is_module "${module}" || kernel_driver_is_builtin "${module}"
}

required_drivers="virtio_blk virtio_pci 9p 9pnet 9pnet_virtio vsock vmw_vsock_virtio_transport"
for module in ${required_drivers}; do
	if ! kernel_driver_is_available "${module}"; then
		echo "Rawhide kernel package is missing driver ${module}" >&2
		exit 1
	fi
done

dracut \
	--force \
	--no-hostonly \
	--omit "crypt dm dmraid" \
	--add-drivers "virtio_pci virtio_blk virtio_net virtio_console virtio_balloon virtio_rng 9p 9pnet 9pnet_virtio vsock vmw_vsock_virtio_transport vmw_vsock_virtio_transport_common" \
	"${initramfs_path}" \
	"${kernel_version}"

if [ ! -f "${initramfs_path}" ]; then
	echo "missing Rawhide initramfs at ${initramfs_path}" >&2
	exit 1
fi

initramfs_drivers="virtio_blk virtio_pci"
for module in ${initramfs_drivers}; do
	if ! kernel_driver_is_module "${module}"; then
		continue
	fi
	if ! lsinitrd "${initramfs_path}" | grep -Eq "/${module}\\.ko(\\.|$)"; then
		echo "Rawhide initramfs is missing ${module}" >&2
		exit 1
	fi
done

if ! qemu-system-x86_64 -machine help | awk '{ print $1 }' | grep -qx 'nitro-enclave'; then
	echo "qemu-system-x86_64 from ${BASE_IMAGE} does not expose the nitro-enclave machine" >&2
	qemu-system-x86_64 --version >&2 || true
	exit 1
fi
if ! vhost-device-vsock --help 2>&1 | grep -q -- '--forward-cid'; then
	echo "vhost-device-vsock from ${BASE_IMAGE} lacks --forward-cid support" >&2
	exit 1
fi

rm -rf "${parent_root}"
mkdir -p "${parent_root}"

tar \
	--one-file-system \
	--xattrs \
	--acls \
	--exclude='./dev' \
	--exclude='./dev/*' \
	--exclude='./proc' \
	--exclude='./proc/*' \
	--exclude='./sys' \
	--exclude='./sys/*' \
	--exclude='./run' \
	--exclude='./run/*' \
	--exclude='./tmp' \
	--exclude='./tmp/*' \
	--exclude='./out' \
	--exclude='./parent-root' \
	--exclude='./var/cache/dnf/*' \
	--exclude='./var/log/*' \
	-C / \
	-cpf - . \
	| tar -xpf - -C "${parent_root}"

mkdir -p \
	"${parent_root}/dev" \
	"${parent_root}/dev/pts" \
	"${parent_root}/dev/shm" \
	"${parent_root}/proc" \
	"${parent_root}/run" \
	"${parent_root}/sys" \
	"${parent_root}/tmp" \
	"${parent_root}/tools" \
	"${parent_root}/work"
chmod 1777 "${parent_root}/tmp"

ln -sf /usr/bin/qemu-system-x86_64 "${parent_root}/tools/qemu-system-x86_64"
ln -sf /usr/bin/vhost-device-vsock "${parent_root}/tools/vhost-device-vsock"

cat > "${parent_root}/init" <<'EOF'
#!/bin/sh
set -eu

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

mkdir -p /dev /dev/pts /dev/shm /proc /run /sys /tmp /work
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs shm /dev/shm 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true

modprobe 9p 2>/dev/null || true
modprobe 9pnet 2>/dev/null || true
modprobe 9pnet_virtio 2>/dev/null || true
modprobe vsock 2>/dev/null || true
modprobe vmw_vsock_virtio_transport_common 2>/dev/null || true
modprobe vmw_vsock_virtio_transport 2>/dev/null || true

mount -t 9p -o trans=virtio,version=9p2000.L qoswork /work
exec /work/nested_parent_init /work/nested-parent.env
EOF
chmod 0755 "${parent_root}/init"

truncate -s "${ROOTFS_SIZE}" "${rootfs_image}"
mke2fs -q -F -t ext4 -L qosparent -m 0 -d "${parent_root}" "${rootfs_image}"

cp "${kernel_path}" /out/vmlinuz

qemu_version=$(qemu-system-x86_64 --version | head -n 1)
vhost_version=$(vhost-device-vsock --version 2>&1 | head -n 1 || true)
cat > /out/rawhide-parent.env <<EOF
QOS_NESTED_NITRO_PARENT_BUNDLE_KIND=qos-nested-nitro-rawhide-parent
QOS_NESTED_NITRO_PARENT_ARCH=x86_64
QOS_NESTED_NITRO_PARENT_BASE_IMAGE=${BASE_IMAGE}
QOS_NESTED_NITRO_PARENT_KERNEL_VERSION=${kernel_version}
QOS_NESTED_NITRO_PARENT_QEMU_VERSION=${qemu_version}
QOS_NESTED_NITRO_PARENT_VHOST_VERSION=${vhost_version}
QOS_NESTED_NITRO_PARENT_ROOTFS=rootfs.ext4
QOS_NESTED_NITRO_PARENT_KERNEL=vmlinuz
QOS_NESTED_NITRO_PARENT_INITRD=initramfs.img
EOF
IN_CONTAINER

tmp_bundle="${bundle_dir}.tmp"
rm -rf "${tmp_bundle}"
mkdir -p "${tmp_bundle}"
tar -cf - -C "${work_dir}" . | tar -xf - -C "${tmp_bundle}"

rm -rf "${bundle_dir}"
mkdir -p "$(dirname -- "${bundle_dir}")"
mv "${tmp_bundle}" "${bundle_dir}"
chmod -R u+rwX "${bundle_dir}"

echo
echo "Nested Nitro Rawhide parent bundle ready:"
echo "  ${bundle_dir}"
echo
echo "Use it with:"
echo "  export QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE=${bundle_dir}"
