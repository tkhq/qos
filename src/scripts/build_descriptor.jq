def ensure($condition; $message):
  if $condition then . else error($message) end;

def image_names:
  ["qos_bridge", "qos_bridge_egress", "qos_client", "qos_enclave", "qos_enclave_egress", "qos_host"];

def registry_prefixes:
  {ecr: "799078726966.dkr.ecr.us-east-1.amazonaws.com/tkhq", ghcr: "ghcr.io/tkhq"};

def source:
  {
    repository: env.GITHUB_REPOSITORY,
    pullRequest: (env.QOS_PR_NUMBER | tonumber),
    headCommit: env.QOS_HEAD_COMMIT,
    testedCommit: env.QOS_TESTED_COMMIT,
    runId: (env.GITHUB_RUN_ID | tonumber),
    runAttempt: (env.GITHUB_RUN_ATTEMPT | tonumber)
  }
  | ensure(.repository == "tkhq/qos"; "build descriptors must come from tkhq/qos")
  | ensure(all(.pullRequest, .runId, .runAttempt; . >= 1 and . == floor); "invalid PR/run identity")
  | ensure(all(.headCommit, .testedCommit; test("^[0-9a-f]{40}$")); "expected full git commit SHAs");

def build_tag:
  "pr-\(.pullRequest)-run-\(.runId)-\(.runAttempt)";

def parse_pcrs:
  split("\n") | map(select(test("\\S")))
  | map(
      ensure(test("^\\s*[0-9a-fA-F]{96}\\s+PCR[012]\\s*$"); "invalid PCR line")
      | capture("^\\s*(?<value>[0-9a-fA-F]{96})\\s+PCR(?<index>[012])\\s*$")
    )
  | ensure((map(.index) | sort) == ["0", "1", "2"]; "expected exactly one measurement for PCR0, PCR1 and PCR2")
  | map({key: ("pcr" + .index), value: (.value | ascii_downcase)}) | from_entries;

def validate_image($name; $source):
  ($name == "qos_enclave" or $name == "qos_enclave_egress") as $enclave
  | ensure((image_names | index($name)) != null; "unexpected image: \($name)")
  | ensure(keys == (["ecr", "ghcr", "buildAttempt"] + (if $enclave then ["pcrs"] else [] end) | sort);
      "\($name): incorrect image metadata fields")
  | ensure(.buildAttempt | type == "number" and . >= 1 and . <= $source.runAttempt and . == floor;
      "\($name): invalid build attempt")
  | .buildAttempt as $attempt
  | ($source | .runAttempt = $attempt | build_tag) as $tag
  | . as $image
  | ensure(all(registry_prefixes | to_entries[];
      . as $registry
      | ($registry.value + "/" + $name + ":" + $tag + "@sha256:") as $prefix
      | $image[$registry.key] | startswith($prefix) and (ltrimstr($prefix) | test("^[0-9a-f]{64}$"))
    ); "\($name): reference must pin this build's image digest")
  | if $enclave then
      ensure(.pcrs | keys == ["pcr0", "pcr1", "pcr2"] and all(.[]; test("^[0-9a-f]{96}$"));
        "\($name): invalid enclave measurements")
    else . end;

def fragment($name; $ecr; $ghcr; $pcrs):
  source as $source
  | {
      ecr: $ecr, ghcr: $ghcr, buildAttempt: $source.runAttempt
    }
  | if $pcrs == null then . else .pcrs = $pcrs end
  | validate_image($name; $source)
  | {schemaVersion: 1, source: $source, images: {($name): .}};

def assemble:
  source as $source
  | reduce .[] as $part ({};
      ($part
        | ensure(keys == ["images", "schemaVersion", "source"] and .schemaVersion == 1;
            "unsupported metadata fragment")
        | ensure((.source | del(.runAttempt)) == ($source | del(.runAttempt));
            "metadata comes from a different build")
        | ensure(.images | length == 1; "expected one image per fragment")
        | .images | to_entries[0]
        | .key as $name
        | .value
        | ensure(.buildAttempt == $part.source.runAttempt; "image attempt does not match its source")
        | validate_image($name; $source)
        | {($name): .}
      ) as $entry
      | ($entry | keys[0]) as $name
      | ensure(has($name) | not; "duplicate image: \($name)")
      | . + $entry
    )
  | ensure(keys == image_names; "incomplete build: missing required images")
  | {schemaVersion: 1, source: $source, supportedManifestVersions: ["v2"], images: .};
