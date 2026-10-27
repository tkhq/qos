#!/bin/bash
# Collect digest-pinned image outputs from one QOS PR workflow run.
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
mode=${1:?usage: build_descriptor.sh <fragment|assemble> [options]}
shift
image_name= ecr_ref= ghcr_ref= pcrs_file= fragments_dir= output_path=
while [[ $# -gt 0 ]]; do
	[[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 1; }
	case "${mode}:$1" in
		fragment:--image) image_name=$2 ;;
		fragment:--ecr) ecr_ref=$2 ;;
		fragment:--ghcr) ghcr_ref=$2 ;;
		fragment:--pcrs-file) pcrs_file=$2 ;;
		assemble:--fragments) fragments_dir=$2 ;;
		fragment:--output|assemble:--output) output_path=$2 ;;
		*) echo "unknown option for ${mode}: $1" >&2; exit 1 ;;
	esac
	shift 2
done
: "${output_path:?--output is required}"
mkdir -p "$(dirname "$output_path")"
temporary_output=$(mktemp "${output_path}.tmp.XXXXXX")
trap 'rm -f "$temporary_output"' EXIT

case "$mode" in
	fragment)
		: "${image_name:?--image is required}" "${ecr_ref:?--ecr is required}" "${ghcr_ref:?--ghcr is required}"
		pcrs=null
		if [[ -n "$pcrs_file" ]]; then
			pcrs=$(jq -Rse -L "$script_dir" 'include "build_descriptor"; parse_pcrs' "$pcrs_file")
		fi
		jq -Sne -L "$script_dir" --arg image "$image_name" --arg ecr "$ecr_ref" --arg ghcr "$ghcr_ref" \
			--argjson pcrs "$pcrs" 'include "build_descriptor"; fragment($image; $ecr; $ghcr; $pcrs)' > "$temporary_output"
		;;
	assemble)
		: "${fragments_dir:?--fragments is required}"
		shopt -s nullglob
		fragments=("$fragments_dir"/*.json)
		[[ ${#fragments[@]} -gt 0 ]] || { echo "incomplete build: no metadata fragments" >&2; exit 1; }
		jq -Sse -L "$script_dir" 'include "build_descriptor"; assemble' "${fragments[@]}" > "$temporary_output"
		;;
	*) echo "unknown command: $mode" >&2; exit 1 ;;
esac
mv "$temporary_output" "$output_path"

if [[ "$mode" == assemble ]]; then
	checksum=(sha256sum)
	if ! command -v sha256sum >/dev/null; then
		checksum=(shasum -a 256)
	fi
	(cd "$(dirname "$output_path")" && "${checksum[@]}" "$(basename "$output_path")") > "${output_path%.*}.sha256"
fi
