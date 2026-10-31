# Workload Mounts

Status: Initial normative specification

An OCI workload uses one tagged `mounts` list for every attachment from the
parent QOS file-system environment.

The mount `type` selects how QOS interprets `source`. This permits Manifest V3
to add new mount kinds without changing existing mount objects.

## Common schema

Each mount MUST contain:

- `type`;
- `source`;
- `mountPath`.

Each mount MAY contain `readOnly`. The default value is `false`.

The initial mount types are:

- `volume`, which mounts a named top-level volume;
- `file`, which mounts a regular file from the parent QOS environment.

QOS MUST reject an unsupported mount type.

`mountPath` MUST be an absolute, normalized path inside the OCI container root
file system.

`mountPath` MUST NOT contain a NUL byte, repeated `/`, a `.` component, or a
`..` component. It MUST NOT be `/`.

A declared workload mount MUST NOT be `/proc`, `/sys`, `/dev`, or a path below
one of those runtime-owned paths.

Two entries in one workload's `mounts` list MUST NOT use duplicate or
overlapping `mountPath` values. The initial feature does not support mounting
one declared workload mount inside another declared workload mount.

The absence of `mounts` means that the workload receives no top-level volume
and no parent QOS file.

## Volume mount

For `type: "volume"`, `source` is the name of a declared top-level volume.

The top-level volume's own `type` selects its storage backend. A tmpfs volume
and a future persistent volume both use mount `type: "volume"`; the workload
does not need a different attachment schema.

```json
{
  "type": "volume",
  "source": "shared-run",
  "mountPath": "/run/shared",
  "readOnly": false
}
```

The complete rules are in [Volumes](volumes.md).

## File mount

For `type: "file"`, `source` is an absolute path to a mountable regular file in
the parent QOS environment.

```json
{
  "type": "file",
  "source": "/qos.quorum.key",
  "mountPath": "/run/qos/quorum.key",
  "readOnly": true
}
```

The complete rules are in [Parent QOS file mounts](file_mounts.md).

## Ordering

QOS MUST attach fixed runtime mounts first. It MUST attach `volume` mounts
second and `file` mounts last.

The order of entries in `mounts` MUST NOT change the effective mount order.

QOS MUST resolve mount targets without following a symbolic link in any path
component. It MUST reject a target that does not remain below the workload root
file system.

## Type evolution

A later Manifest V3 specification MAY add another mount type. It MUST define
the meaning of every common field, all type-specific fields, path conflicts,
ownership, lifecycle, and behavior when `readOnly` is absent.

A later mount type MUST NOT change the meaning of `volume` or `file`.
