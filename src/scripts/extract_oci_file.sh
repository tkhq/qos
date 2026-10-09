#!/bin/sh
# Print a single file from a built OCI image layout to stdout.
#
# Usage: extract_oci_file.sh <oci-layout-dir> <path-in-image>
#
# Walks the index -> manifest -> layers and extracts the first layer
# that contains <path-in-image> (requires jq and tar)
set -eu

dir=${1?usage: extract_oci_file.sh <oci-layout-dir> <path-in-image>}
path=${2?usage: extract_oci_file.sh <oci-layout-dir> <path-in-image>}

blob() { echo "${dir}/blobs/sha256/$(echo "${1}" | cut -d: -f2)"; }

manifest=$(blob "$(jq -r '.manifests[0].digest' "${dir}/index.json")")

for layer in $(jq -r '.layers[].digest' "${manifest}"); do
	if tar -xzOf "$(blob "${layer}")" "${path}" 2>/dev/null; then
		exit 0
	fi
done

echo "extract_oci_file.sh: ${path} not found in ${dir}" >&2
exit 1
