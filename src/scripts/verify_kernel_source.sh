#!/bin/sh
# Verify that the kernel tarball pinned in the linux_nitro Containerfile is
# the release a kernel maintainer signed.
#
# Usage: verify_kernel_source.sh
#
# Reads the tarball URL and sha256 pin from the Containerfile, downloads the
# tarball and its kernel.org signature, checks the pin, then checks the
# signature against the maintainer keys committed in keys/. Only those keys
# are trusted. Requires curl, gpgv, gpg, xz, and sha256sum or shasum.
set -eu

image_dir=src/images/linux_nitro
containerfile=${image_dir}/Containerfile

url=$(grep -o 'https://cdn\.kernel\.org/[^ ]*\.tar\.xz' "${containerfile}")
pin=$(grep -o 'checksum=sha256:[0-9a-f]*' "${containerfile}" | cut -d: -f2)
[ "$(echo "${url}" | wc -l)" -eq 1 ] && [ -n "${url}" ] ||
	{ echo "expected one kernel.org .tar.xz URL in ${containerfile}" >&2; exit 1; }
[ "$(echo "${pin}" | wc -l)" -eq 1 ] && [ "${#pin}" -eq 64 ] ||
	{ echo "expected one sha256 checksum in ${containerfile}" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

curl -fsSL -o "${work}/linux.tar.xz" "${url}"
curl -fsSL -o "${work}/linux.tar.sign" "${url%.xz}.sign"

if command -v sha256sum >/dev/null; then
	actual=$(sha256sum "${work}/linux.tar.xz" | cut -d' ' -f1)
else
	actual=$(shasum -a 256 "${work}/linux.tar.xz" | cut -d' ' -f1)
fi
[ "${actual}" = "${pin}" ] ||
	{ echo "sha256 mismatch for ${url}: pinned ${pin}, got ${actual}" >&2; exit 1; }

cat "${image_dir}"/keys/*.asc | gpg --dearmor > "${work}/keyring.gpg"

# kernel.org signs the uncompressed tar, not the .xz.
xz -dc "${work}/linux.tar.xz" |
	gpgv --keyring "${work}/keyring.gpg" "${work}/linux.tar.sign" -

echo "verified ${url}"
