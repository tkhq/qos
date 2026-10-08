# Lifecycle, Status, and Attestation

Status: Initial normative implementation specification

## Boot sequence

QOS MUST perform these operations in order:

1. Parse Manifest V3 and reject duplicate raw JSON member names.
2. Verify Manifest Set approvals.
3. Validate the enclave type, signed mode, and PCRs.
4. Validate workload and volume names.
5. Validate workload count, pivot hashes, configuration, image digests, and mounts.
6. Receive workload artifacts. OCI artifacts use the Borsh control protocol.
7. Verify every required OCI image and pivot binary before execution.
8. Bind the complete Manifest V3 hash to QOS attestation.
9. Complete normal provisioning or key forwarding.
10. Rotate to the live ephemeral key.
11. Create top-level tmpfs volumes.
12. Prepare the implicit `qos` volume and any required OCI sandbox and `/dev/shm`.
13. Create one runtime bundle for each OCI workload.
14. Attach workload mounts in the order required by their types.
15. Start each pivot directly and each OCI workload with `libcontainer`.

QOS MUST NOT execute image content before image verification succeeds.

QOS MUST NOT expose the quorum key before quorum provisioning succeeds.

QOS MUST NOT expose the implicit `qos` volume before the required live-key
transition. The OCI control protocol specifies image delivery only. Pivot
binary delivery retains the existing V2 content-verification requirements.

Open question: Define the mixed pivot/OCI boot payload encoding. The existing
[OCI control protocol](control_protocol.md) defines only OCI image artifacts.
This manifest update does not add pivot artifacts to that payload.

## Startup failure

Every workload in the initial manifest is required. There is no optional
workload field.

QOS MUST report a workload-specific error when one workload fails to prepare
or start.

If any workload fails during initial preparation or start, QOS MUST fail the
node boot. It MUST stop any workload that it already started. It MUST then
clean all partial workload state.

QOS MUST report the node as ready only after every workload has started.

A successful `libcontainer` start completes the initial start of that
OCI workload. A successful direct launch completes a pivot's initial start.
A later process exit is runtime behavior and follows the workload's
restart policy. The initial feature does not define a health check or readiness
probe.

QOS MAY prepare independent workloads in parallel. The workload object order
does not express a dependency or readiness rule.

## Restart

QOS MUST apply each workload's signed restart value independently.

For `never`, QOS MUST NOT restart the workload after exit.

After a `never` workload exits, QOS MUST collect its termination result
and retain its logical status record. For an OCI workload, QOS MUST unmount
its mounts and remove its container, bundle, and writable root file system.
QOS MUST NOT remove a top-level volume that another workload or parent QOS
process can still use.

For `always`, QOS MUST restart the workload after exit unless the node is
shutting down.

For an OCI restart, QOS MUST delete the stopped container and its mutable bundle
state. It MUST create a fresh writable root file system from the verified image,
reattach the workload's declared mounts, and create a new container instance.

A pivot restart MUST retain its approved binary and launch configuration.
QOS MUST launch the verified binary directly without OCI runtime state.

Top-level volume contents MUST survive a workload restart. Changes to the old
writable root file system MUST NOT survive.

Repeated OCI exits or failed restart attempts MUST use the exponential backoff
defined by the fixed QOS runtime policy. Pivots retain the V2 restart delay.
QOS MUST continue trying after the maximum backoff delay. The `always` policy
does not have a maximum attempt count.

QOS MUST preserve workload identity, type, content approval, configuration,
and volume grants across a restart.

QOS MUST verify that mutable runtime state cannot change the approved image
or pivot binary identity during restart.

## Status

QOS MUST report status by workload name.

Each workload status MUST contain:

- workload name;
- workload type;
- state with value `waiting`, `running`, or `terminated`;
- restart count;
- last non-secret error when one exists.

OCI workload status MUST also contain its approved image digest and image
verification state.

Pivot workload status MUST contain its approved binary hash.

Image verification state MUST be `pending`, `verified`, or `failed`.

`waiting` means that QOS has not started the process or that the workload is
waiting for a restart attempt. Status MUST include the restart-backoff state
when backoff is active.

`running` means that the workload process has executed and has not exited.
Status MUST include its process ID as seen from the parent QOS PID namespace.

`terminated` means that the process exited and QOS will not restart it. Status
MUST include the last termination result.

A normal exit result MUST contain the exact exit code. A signal termination
result MUST contain the signal separately and MUST NOT encode it as
`128 + signal`.

An `always` workload moves from `running` to `waiting` after an exit and while
QOS applies the restart delay. A `never` workload moves from `running` to
`terminated`.

QOS MUST keep status separate for each workload.

QOS MUST NOT include keys, registry credentials, or image bytes in status or
errors.

## Attestation

The attested Manifest V3 hash covers enclave type, mode, PCRs, every workload
object key, pivot hash and configuration, workload type, image reference type,
image digest, restart value, top-level volume, and typed mount.
Workload member order does not change the canonical manifest hash.

Image digests are indirectly bound to attestation through the signed manifest
hash.

Attestation does not claim that a workload is currently healthy or running.
It does not cover current writable-root contents, current volume contents,
restart count, process ID, or runtime status.

The enclave type and mode select the evidence and measurement verification
rules described in [Manifest V3](../manifest/README.md). Debug mode has zero
PCRs and does not establish a measured image identity.
QOS MUST reject evidence that does not match the signed enclave type, mode,
and PCR values.

QOS MUST reject cross-type key forwarding unless a later specification
explicitly defines and approves it.

## Shutdown

QOS MUST stop workload processes before it removes their mounts and bundles.

QOS MUST remove implicit `qos` volume mounts before it releases enclave-owned
key buffers.

QOS MUST unmount top-level tmpfs volumes after all users stop.

QOS MUST remove the shared OCI workload sandbox after every OCI workload has
stopped and before it releases its remaining runtime state.

QOS MUST treat incomplete cleanup as a node error.
