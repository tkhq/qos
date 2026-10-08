# Workloads

Status: Initial normative specification

A workload is one named pivot process or OCI container that QOS manages.

The workload name and container boundaries organize execution and lifecycle
state. They do not create a security trust boundary. The deployer MUST trust
every workload in the manifest.

## Workload identity

Each member key in `workloads` is the workload's signed name and identity.
Each workload value MUST contain `type` and MUST NOT contain `name`.

The initial workload types are `pivot` and `oci`.

QOS MUST reject a workload type that it does not support.

Parsers MUST reject duplicate member names at the raw JSON input boundary,
as defined in [Manifest V3](README.md). No post-decode name uniqueness check
is required.

The name MUST contain 1 to 63 characters. It MUST start and end with a
lowercase ASCII letter or decimal digit. It MAY contain lowercase ASCII
letters, decimal digits, and hyphens.

QOS MUST use the name in status, logs, and runtime state. For OCI workloads,
it MUST also use the name in bundle paths and container IDs.

The name is part of the signed manifest. Changing the name changes the
workload identity.

## Pivot workload fields

A pivot workload MUST contain:

- `type` with value `pivot`;
- `hash`;
- `restart`;
- `bridgeConfig`;
- `args`.

A pivot workload MAY contain `env`. Its absence means an empty environment
map, as in Manifest V2.

`hash`, `bridgeConfig`, `args`, and `env` retain their Manifest V2 meaning.
`hash` approves the pivot binary using the existing V2 hash rules.
`restart` uses the lowercase V3 values defined below.

A pivot runs directly in the parent QOS execution environment using the
existing V2 pivot launch model. QOS MUST verify its binary before execution.
QOS MUST NOT create an OCI root file system, runtime bundle, or container for
a pivot. Pivots do not use the OCI `image` or `mounts` fields.

Top-level volumes are available to pivots through their signed parent
`mountPath`, subject to normal file permissions. Existing V2 QOS key paths
and key availability rules remain unchanged for pivots.

QOS MUST track each pivot by its workload name. One verified binary MAY
satisfy multiple pivots with the same approved hash. QOS MUST reject bridge
configurations that claim the same parent listener twice.

## OCI workload fields

An OCI workload MUST contain:

- `type` with value `oci`;
- `image`;
- `restart`.

An OCI workload MAY contain:

- `mounts`.

The `image` object MUST contain:

- `type` with value `ociManifest`;
- `digest`.

QOS MUST reject an unsupported image-reference type.

For `type: "ociManifest"`, `digest` MUST identify a platform-specific OCI image
manifest. The initial digest algorithm is SHA-256.

The digest MUST have the form `sha256:` followed by exactly 64 lowercase
hexadecimal characters.

QOS MUST verify that the image operating system and architecture can run in
the enclave.

An absent `mounts` list means that the workload receives no top-level volume
or implicit `qos` volume, including QOS keys.

## Restart behavior

Both initial workload types MUST support lowercase `never` and `always`.
V3 MUST reject the V2 spellings `Never` and `Always`.

QOS MUST apply restart behavior independently to each workload.

For `never`, QOS MUST NOT restart the workload after its process exits.

For `always`, QOS MUST restart the workload after every process exit unless
the QOS node is shutting down.

One workload exit MUST NOT stop another workload unless an existing QOS node
failure rule requires node shutdown.

QOS MUST use exponential backoff when an OCI workload repeatedly exits or
fails to restart. The backoff MUST have a fixed maximum delay. It MUST reset
after the workload runs continuously for a fixed stability period. These values are QOS
runtime policy and are not Manifest V3 fields.

Backoff delays restart attempts. It does not change `always` into a finite
retry count. Pivot workloads retain the existing V2 restart delay.

## Multiple workloads

The requirements in this section define normal runtime behavior for trusted
workloads. They are not adversarial guarantees against a workload that attacks
QOS or another workload through the shared Linux kernel.

QOS MUST support separate state for every workload.

Each OCI workload MUST have a separate runtime bundle, container ID, root file
system, process namespace, mount namespace, status record, restart state, and
cleanup path.

One OCI workload MUST NOT modify another OCI workload's root file system.

One OCI workload MUST NOT receive another workload's mount or an undeclared
mount.

The initial schema does not define startup dependencies, health checks, or a
global startup order. Workload object order does not create a dependency. A
later optional field can add those features.

## Process source

The initial OCI workload does not contain a `process` object.

QOS MUST get the command, environment, working directory, and user from the
verified OCI image as defined in [Processes](../runtime/processes.md).

The initial manifest does not override these values.

## Resource fields

The initial workload does not set memory, CPU, or process-count limits.

A PID namespace isolates process identifiers. It does not limit the number of
processes.

QOS MAY apply node-wide safety limits, including a maximum workload count.
QOS MUST reject a manifest that exceeds its workload-count limit. These limits
do not have to be manifest fields.

Future workload types are specified separately in
[Additional workload types](../future/additional_workload_types.md).
