# Parent QOS File Mounts

Status: Initial normative specification

A file mount grants one OCI workload access to one existing regular file from
the parent QOS file-system environment.

A quorum key is not a special mount type. It is a protected parent QOS file
that a workload MAY mount through this mechanism.

## Schema

Each file mount MUST be inside one workload's `mounts` list.

Each file mount MUST contain:

- `type` with value `file`;
- `source`;
- `mountPath`.

Each file mount MAY contain `readOnly`. The default value is `false`.

`source` MUST be an absolute, normalized path in the parent QOS file-system
environment.

`mountPath` MUST be an absolute, normalized path inside the OCI container root
file system.

File mounts MUST follow the common collision rules in
[Workload mounts](mounts.md). A file mount MUST NOT be at, above, or below the
path of another declared workload mount.

## Source policy

The signed manifest grants access to the source path. The host cannot add a
source path or change it after approval.

QOS MUST resolve every source path component from an enclave-owned parent
directory without following a symbolic link. It MUST open and pin the final
source before it creates the container mount.

The pinned source MUST be an existing regular file. QOS MUST reject a
directory, device, socket, FIFO, or symbolic link as a source.

Replacing or deleting the parent path after QOS pins the source MUST NOT change
which file the workload receives. Writes to the pinned file remain visible
according to normal file and mount permissions.

The initial QOS source policy MUST support these protected files:

- `/qos.quorum.key` for the quorum key;
- `/qos.ephemeral.key` for the live ephemeral key;
- `/qos.manifest` for the approved manifest.

QOS MUST NOT expose the setup ephemeral private key through a file mount.

A QOS release MAY permit other regular parent files. The release MUST define
which parent paths are mountable and whether each source permits a writable
mount. The enclave measurement identifies this fixed source policy.

QOS MUST reject `readOnly: false` when the source policy requires a read-only
mount. The quorum key, live ephemeral key, and manifest sources MUST always be
mounted read-only.

## Read and write behavior

QOS MUST bind-mount the pinned source file at `mountPath` by file descriptor or
an equivalent race-free mechanism.

When `readOnly` is `true`, the workload MUST NOT change the file through that
mount.

When `readOnly` is `false`, a workload write changes the parent QOS source
file. Normal file permissions can still deny the write.

The `readOnly` value applies only to this file mount. It does not change the
OCI root file system or a volume mount.

## Target creation

QOS MUST attach runtime mounts first, volume mounts second, and file mounts
last.

QOS MUST resolve every target path component without following a symbolic
link. The resolved target MUST remain below the workload root file system.

QOS MUST create missing parent directories inside the workload root file
system with mode `0755`. It MUST NOT replace a parent directory with a file.

If the final target does not exist, QOS MUST create an empty regular file as
the mount point. If the final target is an existing regular file, QOS MUST
leave that file in place and bind-mount the source over it. The mount obscures
the existing file while the container runs.

QOS MUST reject a symbolic link, directory, device, socket, FIFO, or another
unsupported file type at the final target.

## Ownership and future user namespaces

A file mount preserves the source file's permission mode, UID, and GID. The
manifest does not contain a parent UID or GID.

The initial protected QOS files MUST be readable by every process in a
workload that receives the mount. They SHOULD be owned by parent QOS root with
permission mode `0444`, in addition to the read-only mount restriction.

A future user-namespace implementation MUST make the source ownership valid in
the workload namespace. It MAY use an idmapped bind mount or another mechanism
that preserves the same file contents and read/write behavior.

QOS MUST reject a file mount if it cannot represent the source ownership
safely in the workload namespace. It MUST NOT write parent UID or GID values
into Manifest V3.

A later specification MAY add optional container-relative ownership fields if
they are needed. Their absence MUST preserve the source-metadata behavior in
this document.
