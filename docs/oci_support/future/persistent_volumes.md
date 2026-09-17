# Persistent Volumes

Status: Future normative addendum

This document defines the future manifest shape for persistent volumes. It is
not part of the initial `min-oci-support` conformance requirements.

## Top-level volume shape

A persistent volume is a named top-level resource in the `volumes` object.

```json
{
  "volumes": {
    "database-data": {
      "type": "persistent",
      "mountPath": "/mnt/qos/database-data",
      "sizeMb": "10240",
      "fs": "ext4",
      "luks": true,
      "luksFormatIfCannotFindLuks": false
    }
  }
}
```

The fields have these meanings:

- `type` MUST be `persistent`.
- `mountPath` is the absolute path associated with the volume in the parent
  QOS environment.
- `sizeMb` is the minimum volume size in mebibytes. Its encoding MUST follow
  the normal QOS manifest integer convention.
- `fs` identifies the file system for the volume.
- `luks` selects LUKS encryption for the volume.
- `luksFormatIfCannotFindLuks` selects whether a new LUKS container may be
  created when the volume does not contain one.

The volume name is the stable resource identity. It is the object key in the
signed `volumes` map and is the name used by workload mounts.

## Workload mounts

A workload references a persistent volume through the common `type: "volume"`
mount shape:

```json
{
  "name": "postgres",
  "type": "oci",
  "image": {
    "type": "ociManifest",
    "digest": "sha256:..."
  },
  "mounts": [
    {
      "type": "volume",
      "source": "database-data",
      "mountPath": "/var/lib/postgresql/data",
      "readOnly": false
    }
  ]
}
```

For a persistent volume mount:

- `type` MUST be `volume`;
- `source` MUST name a declared persistent volume;
- `mountPath` MUST be the absolute path inside the workload root file
  system;
- `readOnly` MAY be omitted and defaults to `false`.

The workload mount does not repeat the persistent volume's size, file-system,
encryption, or parent-path fields. Each workload declares its own mounts and
its own `readOnly` value.

## Compatibility

Persistent volumes add `persistent` as a future top-level volume type. They do
not change the workload mount type or the meaning of `source`, `mountPath`, or
`readOnly`.

Persistent volume fields are optional extensions to the initial top-level
volume schema and MUST NOT change the behavior of manifests that do not use
the `persistent` type.
