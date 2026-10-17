# Workload Mounts

Status: Initial normative specification

An OCI workload uses one tagged `mounts` list for its volume and device
attachments.

The mount `type` selects how QOS interprets `source`. This permits Manifest V3
to add new mount kinds without changing existing mount objects.

## Common schema

Each mount MUST contain:

- `type`;
- `source`;
- `mountPath`.

A `volume` mount MAY contain `readOnly`. The default value is `false`. A `qos`
mount MUST explicitly set `readOnly` to `true`. A `device` mount has no other
field.

There are two mount types. `volume` mounts a declared top-level volume or the
reserved implicit `qos` volume. `device` mounts a device QOS provides. The
`type` discriminator remains required so later specifications can add mount
types.

QOS MUST reject an unsupported mount type.

`mountPath` MUST be an absolute, normalized path inside the OCI container root
file system.

`mountPath` MUST NOT contain a NUL byte, repeated `/`, a `.` component, or a
`..` component. It MUST NOT be `/`.

A declared volume mount MUST NOT be `/proc`, `/sys`, `/dev`, or a path below
one of those runtime-owned paths. A device mount's `mountPath` MUST be the
device's own path below `/dev`.

Two entries in one workload's `mounts` list MUST NOT use duplicate or
overlapping `mountPath` values. The initial feature does not support mounting
one declared workload mount inside another declared workload mount.

The absence of `mounts` means that the workload receives no top-level volume,
implicit `qos` volume or device.

## Volume mount

For `type: "volume"`, `source` names a declared top-level volume or `qos`.

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

## Device mount

For `type: "device"`, `source` names a device. The only device is `nsm`, the
Nitro Secure Module, which issues attestation documents; its `mountPath` MUST
be `/dev/nsm`.

```json
{
  "type": "device",
  "source": "nsm",
  "mountPath": "/dev/nsm"
}
```

QOS pins the enclave's device node without opening it, checks that it is a
character device, and binds it read-only at `/dev/nsm` in the workload's
runtime-owned `/dev`. The workload's device policy allows that node, and the
policy of every workload that does not mount it still denies it, including
through a node created with `CAP_MKNOD`.

A workload with the NSM can request attestation documents for any data it
chooses, in the enclave's name. It cannot change a PCR: QOS locks every PCR
before it starts a workload. The workloads of a manifest share one trust
domain ([isolation](../runtime/isolation.md)), so a manifest grants the NSM
only to workloads it trusts to attest for the enclave.

## Ordering

QOS MUST attach fixed runtime mounts first, declared volume mounts second, and
device mounts last.

The order of entries in `mounts` MUST NOT change the effective mount order.

QOS MUST resolve mount targets without following a symbolic link in any path
component. It MUST reject a target that does not remain below the workload root
file system.

## Type evolution

A later Manifest V3 specification MAY add another mount type. It MUST define
the meaning of every common field, all type-specific fields, path conflicts,
ownership, lifecycle, and behavior when `readOnly` is absent.

A later mount type MUST NOT change the meaning of `volume` or `device`.
