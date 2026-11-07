# Volumes

Status: Initial normative specification

Manifest V3 separates a named volume from a container volume mount.

The top-level `volumes` object declares storage in the parent QOS mount
namespace. A workload `mounts` entry with `type: "volume"` grants one container
access to one named volume at a container path.

This structure follows the Kubernetes named-volume and volume-mount model.
It also follows the Docker Compose pattern of declaring a named volume once
and attaching it to each workload that needs it.

## Top-level volumes

The top-level `volumes` field MUST be an object.

Each object key is the unique volume name.

The initial volume object MUST contain:

- `type` with value `tmpfs`;
- `mountPath`.

The name MUST follow the workload name syntax.

The top-level `mountPath` MUST be an absolute path in the parent QOS mount
namespace.

The path MUST be normalized and MUST NOT contain a NUL byte, repeated `/`, a
`.` component, or a `..` component. It MUST NOT be `/`.

The path MUST NOT overlap a QOS key path, manifest path, runtime-state path,
OCI bundle path, or another QOS-owned system mount.

Two top-level volume mount paths MUST NOT overlap.

QOS MUST create each top-level volume once at its signed parent `mountPath`.

QOS MUST resolve the parent path without following a symbolic link. If the
target does not exist, QOS MUST create an empty directory. If it exists, it
MUST be an empty directory owned by QOS. QOS MUST reject another file type or
a nonempty directory.

A `tmpfs` volume is volatile. Its contents are lost when the enclave stops.

QOS MUST create the root of an initial tmpfs volume with mode `01777`. This
fixed mode lets a non-root image process use an empty volume without adding
owner fields to the manifest. Normal file permissions apply to content that a
workload creates in the volume.

The initial schema does not set a per-volume memory limit.

Pivot code and normal QOS processes can use the parent `mountPath`, subject to
normal parent-QOS file permissions.

QOS MUST reject an unsupported volume type.

## Workload volume mounts

Each OCI workload volume mount MUST be in that workload's `mounts` list.

Each entry MUST contain:

- `type` with value `volume`;
- `source`;
- `mountPath`.

Each entry MAY contain `readOnly`. The default value is `false`.

The `source` MUST reference a declared top-level volume name.

The workload `mountPath` MUST be an absolute path inside the container root
file system.

The workload does not specify the parent QOS path. QOS resolves the named
volume to its signed top-level `mountPath`.

QOS MUST implement the entry as a bind mount from the top-level volume into
the workload mount namespace.

QOS MUST apply `readOnly` independently for each workload mount.

QOS MUST reject a mount path that escapes the container root file system.

QOS MUST reject duplicate or overlapping paths between two `volume` mount
entries. The initial feature does not permit a nested relationship with
another mount type.

QOS MUST resolve the workload target without following a symbolic link. If the
target does not exist, QOS MUST create a directory with mode `0755`. If the
target exists, it MUST be a directory.

The mounted volume obscures existing image content at the target, as a
Kubernetes volume mount does. QOS MUST NOT copy that image content into the
volume.

The initial schema does not contain `subPath`, mount propagation, or arbitrary
mount options.

## Access model

A top-level volume declaration creates storage. It does not grant an OCI
workload access.

A workload receives access only through its own signed `mounts` entry with
`type: "volume"`.

The absence of a volume mount means that the workload cannot access that
volume through its mount namespace.

QOS MUST mount workload volumes with `nodev` and `nosuid`. Initial workload
volumes allow execution.

Linux file mode, UID, GID, and supported access-control-list checks apply after
the mount is attached.

The image-selected process user does not change the volume grant. It only
affects file permission checks inside the mounted volume.

## Ownership compatibility

The initial manifest contains no volume-owner, `fsGroup`, parent UID, or parent
GID field.

Any later volume ownership field MUST describe ownership as seen by the
workload. It MUST NOT expose a parent QOS UID or GID.

QOS MUST NOT define a top-level volume name as a parent path alias. The name is
the stable storage identity in the manifest.

This rule permits later user-namespace and persistent-volume behavior without
changing the initial mount schema.

## Initial and future support

| Concern | Initial support | Future support |
| --- | --- | --- |
| Top-level type | `tmpfs` | `persistent` and other tagged types |
| Storage identity | Top-level volume name | Same |
| Container attachment | `mounts[].source` with `type: "volume"` | Same |
| Container path | `mounts[].mountPath` | Same |
| Read-only selection | Per mount | Same |
| Persistence | No | Defined by the future volume type |

Persistent storage is specified in
[Persistent volumes](../future/persistent_volumes.md). It is not part of
initial conformance.
