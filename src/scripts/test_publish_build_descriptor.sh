#!/bin/bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/bin" "$test_dir/fragments"
export GITHUB_REPOSITORY=tkhq/qos QOS_PR_NUMBER=831 GITHUB_RUN_ID=12345 GITHUB_RUN_ATTEMPT=1
export QOS_HEAD_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export QOS_TESTED_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export AWS_CALLS="$test_dir/aws-calls" AWS_FAIL_KEY=
export PATH="$test_dir/bin:$PATH"

cat > "$test_dir/bin/aws" <<'MOCK'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$AWS_CALLS"
if [[ -n "$AWS_FAIL_KEY" && "$*" == *"$AWS_FAIL_KEY"* ]]; then
	echo 'mock S3 conditional write failed' >&2
	exit 1
fi
MOCK
chmod +x "$test_dir/bin/aws"

while IFS= read -r image; do
	args=()
	if [[ "$image" == qos_enclave || "$image" == qos_enclave_egress ]]; then
		jq -nr 'range(0; 3) | "\("a" * 96) PCR\(.)"' > "$test_dir/nitro.pcrs"
		args=(--pcrs-file "$test_dir/nitro.pcrs")
	fi
	ecr=$(jq -nr -L "$script_dir" --arg image "$image" 'include "build_descriptor";
      registry_prefixes.ecr + "/" + $image + ":" + (source | build_tag) + "@sha256:" + ("c" * 64)')
	ghcr=$(jq -nr -L "$script_dir" --arg image "$image" 'include "build_descriptor";
      registry_prefixes.ghcr + "/" + $image + ":" + (source | build_tag) + "@sha256:" + ("d" * 64)')
	bash "$script_dir/build_descriptor.sh" fragment --image "$image" --ecr "$ecr" --ghcr "$ghcr" \
		"${args[@]}" --output "$test_dir/fragments/$image.json"
done < <(jq -nr -L "$script_dir" 'include "build_descriptor"; image_names[]')
bash "$script_dir/build_descriptor.sh" assemble --fragments "$test_dir/fragments" --output "$test_dir/qos-build.json"
cp "$test_dir/qos-build.json" "$test_dir/pristine.json"
cp "$test_dir/qos-build.sha256" "$test_dir/pristine.sha256"

publish() {
	bash "$script_dir/publish_build_descriptor.sh" "$test_dir" test-bucket
}

expect_failure() {
	if "$@" > "$test_dir/stdout" 2> "$test_dir/stderr"; then
		echo "expected failure: $*" >&2
		exit 1
	fi
}

publish
cat > "$test_dir/expected-calls" <<EOF_CALLS
s3api put-object --bucket test-bucket --key qos/builds/pr-831-run-12345-1/qos-build.sha256 --body $test_dir/qos-build.sha256 --content-type text/plain --if-none-match *
s3api put-object --bucket test-bucket --key qos/builds/pr-831-run-12345-1/qos-build.json --body $test_dir/qos-build.json --content-type application/json --if-none-match *
EOF_CALLS
cmp "$test_dir/expected-calls" "$AWS_CALLS"
echo "PASS: exact immutable keys, checksum-first order and conditional writes"

for filter in \
	'.source.pullRequest = 999' \
	'.source.runId = 12346' \
	'.source.runAttempt = 2' \
	'.source.testedCommit = ("c" * 40)' \
	'.images.qos_host.ecr |= split("@")[0]' \
	'del(.images.qos_enclave.pcrs)' \
	'del(.images.qos_bridge)' \
	'.supportedManifestVersions = ["v3"]'; do
	: > "$AWS_CALLS"
	jq "$filter" "$test_dir/pristine.json" > "$test_dir/qos-build.json"
	expect_failure publish
	[[ ! -s "$AWS_CALLS" ]]
done
cp "$test_dir/pristine.json" "$test_dir/qos-build.json"
echo "PASS: invalid descriptors cannot trigger uploads"

: > "$AWS_CALLS"
printf '\n' >> "$test_dir/qos-build.json"
expect_failure publish
[[ ! -s "$AWS_CALLS" ]]
cp "$test_dir/pristine.json" "$test_dir/qos-build.json"
printf 'invalid checksum\n' > "$test_dir/qos-build.sha256"
expect_failure publish
[[ ! -s "$AWS_CALLS" ]]
cp "$test_dir/pristine.sha256" "$test_dir/qos-build.sha256"
echo "PASS: corrupted descriptor and checksum cannot trigger uploads"

: > "$AWS_CALLS"
AWS_FAIL_KEY=qos-build.sha256 expect_failure publish
[[ $(wc -l < "$AWS_CALLS") -eq 1 ]]
[[ $(cat "$AWS_CALLS") != *qos-build.json* ]]
: > "$AWS_CALLS"
AWS_FAIL_KEY=qos-build.json expect_failure publish
[[ $(wc -l < "$AWS_CALLS") -eq 2 ]]
echo "PASS: denied or conflicting writes fail without an overwrite fallback"
