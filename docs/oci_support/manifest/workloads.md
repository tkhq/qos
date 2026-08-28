# OCI Workloads

Status: Initial normative specification

An OCI workload is one named container that QOS manages.

The workload name and container boundaries organize execution and lifecycle
state. They do not create a security trust boundary. The deployer MUST trust
every workload in the manifest.

## Workload identity

Each workload MUST contain `name` and `type`.

The initial workload `type` is `oci`.

QOS MUST reject a workload type that it does not support.

The workload name MUST be unique in the manifest.

The name MUST contain 1 to 63 characters. It MUST start and end with a
lowercase ASCII letter or decimal digit. It MAY contain lowercase ASCII
letters, decimal digits, and hyphens.

QOS MUST use the name in status, logs, bundle paths, runtime state paths, and
container IDs.

QOS MUST NOT use the workload list index as the stable identity.

The name is part of the signed manifest. Changing the name changes the
workload identity.

## OCI workload fields

An OCI workload MUST contain:

- `name`;
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
and no parent QOS file, including QOS keys.

## Restart behavior

The initial schema MUST support `never` and `always`.

QOS MUST apply restart behavior independently to each workload.

For `never`, QOS MUST NOT restart the workload after its process exits.

For `always`, QOS MUST restart the workload after every process exit unless
the QOS node is shutting down.

One workload exit MUST NOT stop another workload unless an existing QOS node
failure rule requires node shutdown.

QOS MUST use exponential backoff when a workload repeatedly exits or fails to
restart. The backoff MUST have a fixed maximum delay and MUST reset after the
workload runs continuously for a fixed stability period. These values are QOS
runtime policy and are not Manifest V3 fields.

Backoff delays restart attempts. It does not change `always` into a finite
retry count.

## Multiple workloads

The requirements in this section define normal runtime behavior for trusted
workloads. They are not adversarial guarantees against a workload that attacks
QOS or another workload through the shared Linux kernel.

QOS MUST support separate state for every workload.

Each OCI workload MUST have a separate runtime bundle, container ID, root file
system, process namespace, mount namespace, status record, restart state, and
cleanup path.

One workload MUST NOT modify another workload's root file system.

One workload MUST NOT receive another workload's mount or an undeclared mount.

The initial schema does not define startup dependencies, health checks, or a
global startup order. Workload list order does not create a dependency. A
later optional field can add those features.

## Process source

The initial workload does not contain a `process` object.

QOS MUST get the command, environment, working directory, and user from the
verified OCI image as defined in [Processes](../runtime/processes.md).

The initial manifest does not override these values.

## Resource fields

The initial workload does not set memory, CPU, or process-count limits.

A PID namespace isolates process identifiers. It does not limit the number of
processes.

QOS MAY apply node-wide safety limits. These limits do not have to be manifest
fields.

Future workload types are specified separately in
[Additional workload types](../future/additional_workload_types.md).
