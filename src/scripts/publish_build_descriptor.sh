#!/bin/bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
descriptor_dir=${1:?usage: publish_build_descriptor.sh <descriptor-directory> <bucket>}
bucket=${2:?bucket is required}
build_id=$(jq -er -L "$script_dir" 'include "build_descriptor"; validate_descriptor | .source | build_tag' \
	"$descriptor_dir/qos-build.json")
checksum=(sha256sum)
if ! command -v sha256sum >/dev/null; then
	checksum=(shasum -a 256)
fi
expected_checksum=$(cd "$descriptor_dir" && "${checksum[@]}" qos-build.json)
[[ $(cat "$descriptor_dir/qos-build.sha256") == "$expected_checksum" ]] || {
	echo "build descriptor checksum mismatch" >&2
	exit 1
}
prefix="qos/builds/$build_id"
aws s3api put-object --bucket "$bucket" --key "$prefix/qos-build.sha256" \
	--body "$descriptor_dir/qos-build.sha256" --content-type text/plain --if-none-match '*' >/dev/null
aws s3api put-object --bucket "$bucket" --key "$prefix/qos-build.json" \
	--body "$descriptor_dir/qos-build.json" --content-type application/json --if-none-match '*' >/dev/null
