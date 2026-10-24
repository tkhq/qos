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

# Simple utility function to get the path to a blob by its digest.
# For example: blob "sha256:abcd1234" returns ${dir}/blobs/sha256/abcd1234
blob() { echo "${dir}/blobs/sha256/$(echo "${1}" | cut -d: -f2)"; }

# Returns the manifest file path (there's only 1 manifest in the index)
manifest=$(blob "$(jq -r '.manifests[0].digest' "${dir}/index.json")")

# For each layer in the manifest, try to extract the requested file with `tar`
for layer in $(jq -r '.layers[].digest' "${manifest}"); do
	# tar options: -x (extract), -z (gzip), -O (write to stdout), -f (file)
	# (if the file is found we write it to stdout and exit successfully)
	if tar -xzOf "$(blob "${layer}")" "${path}" 2>/dev/null; then
		exit 0
	fi
done

# If we've gone through all the layers and failed to find the file: it's not there.
echo "extract_oci_file.sh: ${path} not found in ${dir}" >&2
exit 1
