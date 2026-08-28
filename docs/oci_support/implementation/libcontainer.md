# Container Execution with `libcontainer`

Status: Initial normative implementation specification

QOS uses an upstream release of `libcontainer` to enforce a QOS-generated OCI
runtime configuration. The dependency version is selected and locked by the
QOS codebase. It is not part of Manifest V3.

The initial feature MUST NOT require a QOS-specific fork of `libcontainer`.
QOS-specific behavior MUST use public `libcontainer` APIs or QOS-owned code.

## Responsibility split

The verified OCI image supplies application content and process defaults.

Manifest V3 supplies approved workload identity, image identity, named volume
mounts, parent-QOS file mounts, and restart behavior.

QOS supplies the fixed container hardening policy.

QOS MUST generate OCI runtime `config.json`.

QOS MUST NOT accept an arbitrary `config.json` from the host or image.

The QOS codebase selects the OCI Runtime Specification value written to
`ociVersion`. Manifest V3 does not select it.

## Bundle creation

QOS MUST create one OCI runtime bundle for each OCI workload.

Each bundle MUST have its own directory and container ID.

Each bundle MUST contain the verified root file system and QOS-generated
`config.json`.

QOS MUST derive bundle and runtime-state paths from the validated workload
name.

QOS MUST prevent the name from escaping the bundle or runtime-state root.

QOS MUST NOT reuse mutable runtime state between workloads.

## OCI workload sandbox

Before it creates an OCI workload container, QOS MUST create one internal
workload sandbox that owns the shared network, IPC, and UTS namespaces and the
shared `/dev/shm` mount.

The sandbox is QOS runtime state. It is not a Manifest V3 workload and does not
run image code.

Each generated OCI configuration MUST join the sandbox network, IPC, and UTS
namespaces by namespace path. It MUST request a new PID and mount namespace for
the individual OCI workload.

The sandbox MUST remain alive across individual workload exits and restarts.
If QOS loses a required sandbox namespace, it MUST treat the node as failed
and stop the OCI workload group.

## Runtime configuration

The generated process configuration MUST follow
[Processes](../runtime/processes.md).

The generated Linux configuration MUST follow
[Initial container separation and hardening](../runtime/isolation.md).

QOS MUST translate each `mounts` entry according to its `type`.

For `type: "volume"`, QOS MUST bind-mount the resolved named top-level volume.

For `type: "file"`, QOS MUST bind-mount the approved parent QOS regular file.

QOS MUST create all mounts before the application can read their paths.

QOS MUST order mounts so that fixed runtime mounts come first, declared volume
mounts come second, and parent-QOS file mounts come last. Declared workload
mount paths MUST NOT overlap.

QOS MUST make the runtime root path refer only to the verified workload root
file system.

QOS MUST omit host or image hooks and every runtime setting that this
specification does not define. It MUST NOT copy a runtime setting from an
image.

QOS MUST include every namespace, mount, capability, and device setting
required by the fixed QOS runtime policy. If `libcontainer` or the kernel
cannot apply a required setting, QOS MUST reject workload start. It MUST NOT
omit the setting or join a parent namespace as a fallback.

The initial generated configuration MUST NOT contain a seccomp filter. QOS
MUST NOT copy one from the host or image.

## Container operations

For each OCI workload, QOS MUST use `libcontainer` to:

1. Validate the container ID and bundle.
2. Create the container.
3. Start the initial process.
4. Observe process exit.
5. Delete the container and runtime state.

QOS MUST treat a partial create or start as a cleanup-required state.

QOS MUST record the container state by workload name.

QOS MUST NOT execute the workload directly with `chroot` as a substitute for a
failed `libcontainer` operation.

QOS MAY select an upstream `libcontainer` no-pivot mode before container
creation when the enclave root file system cannot use `pivot_root`. This is a
configured `libcontainer` root transition, not a fallback after container
creation fails.

## Process and signal behavior

The image entrypoint process is PID 1 inside its PID namespace.

QOS MUST collect its exit status.

QOS MUST use the stop signal and timeout defined in
[Processes](../runtime/processes.md).

When the container PID 1 exits, QOS MUST wait for the `libcontainer` init
process, collect its termination result, ensure that no process remains in the
container PID namespace, and remove remaining runtime state.

## Cleanup

QOS MUST unmount workload volume and file mounts during cleanup.

QOS MUST remove the bundle root file system and generated configuration after
the workload no longer needs them.

QOS MUST NOT delete a top-level volume while another workload or parent QOS
process still uses it.

QOS MUST remove the shared OCI workload sandbox only after every OCI workload
has stopped and released its shared namespace and `/dev/shm` references.

Cleanup MUST be idempotent.
