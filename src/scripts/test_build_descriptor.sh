#!/bin/bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
producer="$script_dir/build_descriptor.sh"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
fragments_dir="$test_dir/metadata"
pristine_dir="$test_dir/pristine"
mkdir -p "$fragments_dir" "$pristine_dir"

export GITHUB_REPOSITORY=tkhq/qos QOS_PR_NUMBER=831 GITHUB_RUN_ID=12345 GITHUB_RUN_ATTEMPT=1
export QOS_HEAD_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export QOS_TESTED_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
digest_c=$(printf 'c%.0s' {1..64})
digest_d=$(printf 'd%.0s' {1..64})
ecr=$(jq -nr -L "$script_dir" 'include "build_descriptor"; registry_prefixes.ecr')
ghcr=$(jq -nr -L "$script_dir" 'include "build_descriptor"; registry_prefixes.ghcr')
tag=$(jq -nr -L "$script_dir" 'include "build_descriptor"; source | build_tag')
images_json=$(jq -nc -L "$script_dir" 'include "build_descriptor"; image_names')
images=()
while IFS= read -r image; do
	images+=("$image")
done < <(jq -r '.[]' <<< "$images_json")
pcrs_file="$test_dir/nitro.pcrs"
jq -nr 'range(0; 3) | "\(((. + 1) | tostring) * 96) PCR\(.)"' > "$pcrs_file"

expect_failure() {
	local message=$1
	shift
	if "$@" > "$test_dir/stdout" 2> "$test_dir/stderr"; then
		echo "expected failure: $*" >&2
		exit 1
	fi
	if [[ $(cat "$test_dir/stderr") != *"$message"* ]]; then
		cat "$test_dir/stderr" >&2
		echo "expected error containing: $message" >&2
		exit 1
	fi
}

assemble() {
	bash "$producer" assemble --fragments "$fragments_dir" --output "$test_dir/qos-build.json"
}

mutate() {
	local name=$1 filter=$2
	jq "$filter" "$pristine_dir/$name.json" > "$fragments_dir/$name.json"
}

# Exercise the public commands, including measurement parsing and exact JSON output.
for image in "${images[@]}"; do
	pcr_args=()
	if [[ "$image" == qos_enclave || "$image" == qos_enclave_egress ]]; then
		pcr_args=(--pcrs-file "$pcrs_file")
	fi
	bash "$producer" fragment --image "$image" \
		--ecr "$ecr/$image:$tag@sha256:$digest_c" --ghcr "$ghcr/$image:$tag@sha256:$digest_d" \
		"${pcr_args[@]}" --output "$fragments_dir/$image.json"
done
cp "$fragments_dir/"*.json "$pristine_dir/"
assemble
jq -ne --arg ecr "$ecr" --arg ghcr "$ghcr" --arg tag "$tag" --arg c "$digest_c" --arg d "$digest_d" \
	--argjson images "$images_json" \
	--slurpfile actual "$test_dir/qos-build.json" '
  {
    schemaVersion: 1,
    source: {
      repository: "tkhq/qos", pullRequest: 831,
      headCommit: ("a" * 40), testedCommit: ("b" * 40), runId: 12345, runAttempt: 1
    },
    supportedManifestVersions: ["v2"],
    images: ($images
      | map(. as $name | {
          key: $name,
          value: ({ecr: "\($ecr)/\($name):\($tag)@sha256:\($c)",
            ghcr: "\($ghcr)/\($name):\($tag)@sha256:\($d)", buildAttempt: 1}
            + if startswith("qos_enclave") then {pcrs: {pcr0: ("1" * 96), pcr1: ("2" * 96), pcr2: ("3" * 96)}} else {} end)
        }) | from_entries)
  } == $actual[0]
' > /dev/null
if command -v sha256sum >/dev/null; then
	(cd "$test_dir" && sha256sum -c qos-build.sha256)
else
	(cd "$test_dir" && shasum -a 256 -c qos-build.sha256)
fi
echo "PASS: descriptor round trip and checksum"

rm "$fragments_dir/qos_bridge_egress.json"
expect_failure "incomplete build" assemble
cp "$pristine_dir/qos_bridge_egress.json" "$fragments_dir/"
cp "$pristine_dir/qos_host.json" "$fragments_dir/duplicate.json"
expect_failure "duplicate image" assemble
rm "$fragments_dir/duplicate.json"
echo "PASS: incomplete and duplicate image sets rejected"

for filter in \
	'.source.repository = "someone/qos"' \
	'.source.pullRequest = 832' \
	'.source.headCommit = ("e" * 40)' \
	'.source.testedCommit = ("f" * 40)' \
	'.source.runId = 12346'; do
	mutate qos_host "$filter"
	expect_failure "different build" assemble
done
cp "$pristine_dir/qos_host.json" "$fragments_dir/"
echo "PASS: mixed build provenance rejected"

for filter in \
	'del(.images.qos_enclave.pcrs)' \
	'.images.qos_enclave.pcrs.pcr0 = "bad"' \
	'.images.qos_enclave.extra = "value"' \
	'.source.runAttempt = 0 | .images.qos_enclave.buildAttempt = 0'; do
	mutate qos_enclave "$filter"
	expect_failure "qos_enclave:" assemble
done
for filter in \
	'.images.qos_enclave.ecr |= split("@")[0]' \
	'.images.qos_enclave.ecr |= sub("/qos_enclave:"; "/other:")' \
	'.images.qos_enclave.ghcr |= sub("run-12345"; "run-999")'; do
	mutate qos_enclave "$filter"
	expect_failure "must pin this build" assemble
done
cp "$pristine_dir/qos_enclave.json" "$fragments_dir/"
echo "PASS: measurements, metadata fields and pinned image identities checked"

# Reuse successful jobs from attempt 1, replacing the failed job with attempt 2.
mutate qos_host '
  .source.runAttempt = 2 | .images.qos_host.buildAttempt = 2
  | .images.qos_host.ecr |= sub("run-12345-1@"; "run-12345-2@")
  | .images.qos_host.ghcr |= sub("run-12345-1@"; "run-12345-2@")
'
GITHUB_RUN_ATTEMPT=2 assemble
jq -e '.source.runAttempt == 2 and .images.qos_host.buildAttempt == 2 and .images.qos_enclave.buildAttempt == 1' \
	"$test_dir/qos-build.json" > /dev/null
expect_failure "invalid build attempt" assemble
cp "$pristine_dir/qos_host.json" "$fragments_dir/"
mutate qos_host '.source.runAttempt = 2'
GITHUB_RUN_ATTEMPT=2 expect_failure "attempt does not match" assemble
cp "$pristine_dir/qos_host.json" "$fragments_dir/"
echo "PASS: reruns preserve per-image attempts and reject inconsistent attempts"

fragment_with_pcrs() {
	bash "$producer" fragment --image qos_enclave \
		--ecr "$ecr/qos_enclave:$tag@sha256:$digest_c" \
		--ghcr "$ghcr/qos_enclave:$tag@sha256:$digest_d" \
		--pcrs-file "$1" --output "$test_dir/enclave.json"
}
head -n 2 "$pcrs_file" > "$test_dir/incomplete.pcrs"
expect_failure "exactly one measurement" fragment_with_pcrs "$test_dir/incomplete.pcrs"
cat "$pcrs_file" "$pcrs_file" > "$test_dir/duplicate.pcrs"
expect_failure "exactly one measurement" fragment_with_pcrs "$test_dir/duplicate.pcrs"
echo 'invalid PCR0' > "$test_dir/invalid.pcrs"
expect_failure "invalid PCR line" fragment_with_pcrs "$test_dir/invalid.pcrs"
echo "PASS: invalid and duplicate PCR lines rejected"

# Exercise the same OCI-layout PCR extraction path used by CI.
mkdir -p "$test_dir/layout/blobs/sha256" "$test_dir/root"
cp "$pcrs_file" "$test_dir/root/nitro.pcrs"
tar -czf "$test_dir/layout/blobs/sha256/layer" -C "$test_dir/root" nitro.pcrs
echo '{"layers":[{"digest":"sha256:layer"}]}' > "$test_dir/layout/blobs/sha256/manifest"
echo '{"manifests":[{"digest":"sha256:manifest"}]}' > "$test_dir/layout/index.json"
sh "$script_dir/extract_oci_file.sh" "$test_dir/layout" nitro.pcrs > "$test_dir/extracted.pcrs"
cmp "$pcrs_file" "$test_dir/extracted.pcrs"
fragment_with_pcrs "$test_dir/extracted.pcrs"
echo "PASS: existing OCI-layout PCR extractor feeds the producer"
