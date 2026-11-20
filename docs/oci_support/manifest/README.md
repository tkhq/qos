# Manifest V3

Status: Initial normative specification

Manifest V3 enables `min-oci-support`. It reuses the QOS control-plane model
from Manifest V2 and replaces the single V2 pivot with a list of named
workloads.

## Relationship to Manifest V2

Manifest V3 reuses these Manifest V2 fields and their existing meaning:

- `namespace`;
- `manifestSet`;
- `shareSet`;
- optional `dns`.

The `namespace` field is the existing QOS namespace. OCI support does not
introduce it.

Manifest V3 MUST use the existing approval, quorum provisioning, key
forwarding, and attestation rules unless this specification changes a rule.

Manifest V2 has one `pivot` field. Manifest V3 replaces `pivot` with a
`workloads` list.

Manifest V2 has an untagged Nitro `enclave` configuration. Manifest V3 adds a
required `type` discriminator to `enclave`.

Manifest V1 and Manifest V2 remain unchanged.

## Top-level fields

Manifest V3 MUST contain:

- `version`;
- `namespace`;
- `manifestSet`;
- `shareSet`;
- `enclave`;
- `workloads`.

Manifest V3 MAY contain:

- `dns`;
- `volumes`.

The `version` value MUST be `v3`.

The `workloads` list MUST contain at least one workload.

An absent `volumes` object means that the manifest declares no top-level
volumes.

## Enclave type

The `enclave` object MUST contain `type`.

Initial `min-oci-support` supports `type` equal to `nitro`.

For `type` equal to `nitro`, the other fields retain their existing Nitro
meaning.

The `type` value is part of the signed manifest.

QOS MUST reject an enclave type that it does not support.

A later Manifest V3 specification MAY add another enclave type. That
specification MUST define its configuration, evidence format, measurements,
and attestation verification rules.

Adding an enclave type MUST NOT change the meaning of `nitro` or require
Manifest V4.

## Initial workload and volume fields

The `workloads` list contains the objects defined in
[OCI workloads](workloads.md).

The optional top-level `volumes` object contains the objects defined in
[Volumes](volumes.md).

Each initial workload has `type` equal to `oci`.

Each initial workload MAY contain the tagged `mounts` list defined in
[Workload mounts](mounts.md).

## Tagged Manifest V3 objects

New Manifest V3 objects use `type` when the object has, or can reasonably gain,
more than one semantic variant.

| Object | Initial type values |
| --- | --- |
| `enclave` | `nitro` |
| workload | `oci` |
| workload `image` | `ociManifest` |
| top-level volume | `tmpfs` |
| workload mount | `volume`, `file` |

Manifest V2 records that V3 reuses without a semantic change do not gain a
`type` field.

## Complete example

This example uses the existing Manifest V2 control-plane fields without
redefining their inner schemas.

```json
{
  "version": "v3",
  "namespace": {
    "name": "payments",
    "nonce": "12",
    "quorumKey": "..."
  },
  "manifestSet": {
    "threshold": "2",
    "members": [
      {
        "alias": "manifest-member-1",
        "pubKey": "..."
      },
      {
        "alias": "manifest-member-2",
        "pubKey": "..."
      }
    ]
  },
  "shareSet": {
    "threshold": "2",
    "members": [
      {
        "alias": "share-member-1",
        "pubKey": "..."
      },
      {
        "alias": "share-member-2",
        "pubKey": "..."
      }
    ]
  },
  "enclave": {
    "type": "nitro",
    "pcr0": "...",
    "pcr1": "...",
    "pcr2": "...",
    "pcr3": "...",
    "awsRootCertificate": "...",
    "qosCommit": "..."
  },
  "volumes": {
    "shared-run": {
      "type": "tmpfs",
      "mountPath": "/mnt/qos/shared-run"
    }
  },
  "workloads": [
    {
      "name": "database",
      "type": "oci",
      "image": {
        "type": "ociManifest",
        "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      },
      "restart": "always",
      "mounts": [
        {
          "type": "volume",
          "source": "shared-run",
          "mountPath": "/run/shared",
          "readOnly": false
        }
      ]
    },
    {
      "name": "api",
      "type": "oci",
      "image": {
        "type": "ociManifest",
        "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
      },
      "restart": "always",
      "mounts": [
        {
          "type": "volume",
          "source": "shared-run",
          "mountPath": "/run/shared",
          "readOnly": true
        },
        {
          "type": "file",
          "source": "/qos.quorum.key",
          "mountPath": "/run/qos/quorum.key",
          "readOnly": true
        }
      ]
    }
  ]
}
```

## Signing and attestation

The normal QOS manifest encoding and approval rules apply to Manifest V3.

The signed manifest MUST cover every workload name, workload type, image
reference type, image digest, restart value, top-level volume, and typed mount.

The QOS attestation document MUST bind the complete Manifest V3 hash.

The normal QOS attestation does not prove that a workload is currently
running. It proves the approved configuration and measured QOS environment.

## Evolution

Every object that selects one of several semantic variants MUST contain a
required `type` field. Initial examples include enclave, workload, volume, and
mount objects. The OCI image reference uses `type` so later support can
distinguish a platform-specific manifest from another OCI descriptor.

A plain record does not need `type` when it has one meaning and no variant is
expected. Existing Manifest V2 records keep their existing schema.

A `type` value is stable after publication. A later specification MAY add a
new value. It MUST NOT reinterpret an existing value.

A later specification MAY mark a type as deprecated. A deprecated type keeps
its defined meaning and remains readable by implementations that claim
backward compatibility. Removing it requires a later manifest version.

A new optional field MUST define its behavior when absent.

An implementation that supports a later Manifest V3 extension MUST continue to
accept earlier valid Manifest V3 documents.

An earlier implementation does not have to accept a newer field or tagged
type.

An initial implementation MUST reject every unknown field in a Manifest V3
object and every unknown tagged type.

A later implementation MAY accept a new field or tagged type only when a
Manifest V3 extension defines it and the implementation supports that
extension. This rule does not change the OCI rule for unknown fields inside a
verified OCI image configuration.
