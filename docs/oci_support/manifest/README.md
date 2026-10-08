# Manifest V3

Status: Initial normative specification

Manifest V3 enables `min-oci-support`. It reuses the QOS control-plane model
from Manifest V2 and replaces the single V2 pivot with an object keyed by
workload name. V3 is not stable until it is verified with OCI workloads.

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
`workloads` object.

Manifest V2 has an untagged Nitro `enclave` configuration. Manifest V3 adds a
required `type` discriminator and signed `mode` to `enclave`. Enclave-wide
mode replaces the V2 pivot debug flag.

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

The `workloads` field MUST be an object with at least one workload.

Parsers MUST reject duplicate JSON member names at the raw input boundary,
before decoding objects into maps. This applies to every Manifest V3 object.
Member names that use different JSON escapes for the same name are duplicates.
A decoded-map uniqueness check cannot recover overwritten input members.

A QOS release MAY set a maximum workload count. It MUST reject a manifest
that exceeds that limit before starting any workload.

An absent `volumes` object means that the manifest declares no top-level
volumes.

## Enclave type and mode

The `enclave` object MUST contain `type` and `mode`.

Initial `min-oci-support` supports `type` equal to `nitro`.

For `nitro`, `mode` MUST be `attested` or `debug`. Both values are signed.
QOS MUST reject a missing or unsupported mode.

Both modes MUST contain `pcr0`, `pcr1`, `pcr2`, and `pcr3`.
Each PCR MUST be a hexadecimal string encoding 48 bytes (96 hex characters).
The existing Nitro fields `awsRootCertificate` and `qosCommit` retain their
Manifest V2 meaning and remain required.

In `attested` mode, the PCRs specify the expected Nitro measurements. PCR0
measures the enclave image. PCR1 measures the kernel and bootstrap. PCR2
measures the application. PCR3 measures the associated EC2 instance IAM role.
Verification MUST compare evidence against these approved PCR values using
the existing Nitro verification rules. Attested verification MUST reject
zero-PCR debug evidence.

In `debug` mode, every PCR value MUST contain exactly 96 hex zeros. QOS MUST
reject a debug manifest with any nonzero PCR. Verification MUST compare
evidence against the approved zero values using the existing Nitro rules.
Nitro debug evidence has zero PCR0 through PCR3 values. These values do not
establish the measured image, kernel, application, or IAM-role identity of an
attested enclave. The signed mode distinguishes this
debug identity from the approved measured configuration. Debug mode MUST NOT
bypass manifest approval or workload-content verification.

The Manifest V2 pivot debug flag controls whether the reaper pipes and
reprints pivot output. Visible output also requires enclave logging settings.
It does not select expected PCRs or bypass PCR comparison. See the
[V2 pivot schema](../../../src/qos_core/src/protocol/services/boot/manifest/v2.rs)
[reaper](../../../src/qos_core/src/reaper.rs), and
[Nitro PCR verification](../../../src/qos_nsm/src/nitro/mod.rs).
V3 makes debug identity an enclave-wide decision instead of a per-pivot flag.
Workload values MUST NOT contain a debug-mode field.

Open question: Should V3 `enclave.mode` also select V2-style pivot output
logging? This specification does not yet define that mapping.

QOS MUST reject an enclave type that it does not support.

A later Manifest V3 specification MAY add another enclave type. That
specification MUST define its configuration, evidence format, measurements,
and attestation verification rules.

Adding an enclave type MUST NOT change the meaning of `nitro` or require
Manifest V4.

## Initial workload and volume fields

The `workloads` object maps signed workload names to the values defined in
[Workloads](workloads.md). Workload values have no `name` field.

The optional top-level `volumes` object contains the objects defined in
[Volumes](volumes.md).

Each initial workload has `type` equal to `pivot` or `oci`.

Each OCI workload MAY contain the tagged `mounts` list defined in
[Workload mounts](mounts.md).

## Tagged Manifest V3 objects

New Manifest V3 objects use `type` when the object has, or can reasonably gain,
more than one semantic variant.

| Object | Initial type values |
| --- | --- |
| `enclave` | `nitro` |
| workload | `pivot`, `oci` |
| workload `image` | `ociManifest` |
| top-level volume | `tmpfs` |
| workload mount | `volume` |

Manifest V2 records that V3 reuses without a semantic change do not gain a
`type` field.

## Complete example

This example uses the existing Manifest V2 control-plane fields without
redefining their inner schemas. It uses the RFC's pivot and OCI workloads,
shared tmpfs volume, and implicit `qos` volume. Certificate and key values are
placeholders. The debug PCR values are written in full.

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
    "mode": "debug",
    "pcr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "pcr1": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "pcr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "pcr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "awsRootCertificate": "...",
    "qosCommit": "..."
  },
  "volumes": {
    "shared-run": {
      "type": "tmpfs",
      "mountPath": "/mnt/qos/shared-run"
    }
  },
  "workloads": {
    "control-service": {
      "type": "pivot",
      "hash": "6851e7d5d3200c971307b7f3d02c35dc685413215392f1b35fa5ecb53264d963",
      "restart": "always",
      "bridgeConfig": [],
      "args": []
    },
    "api": {
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
        },
        {
          "type": "volume",
          "source": "qos",
          "mountPath": "/run/qos",
          "readOnly": true
        }
      ]
    }
  }
}
```

## Signing and attestation

Manifest V3 uses QOS canonical JSON encoding and the existing approval rules.
Canonical JSON sorts object keys. Reordering `workloads` members MUST NOT
change the manifest hash. Renaming a workload MUST change the manifest hash.

An array of workload values was rejected because array order affects the hash
and requires a separate workload-name uniqueness check.

The signed manifest MUST cover enclave type, mode, PCRs, every workload name,
pivot hash and configuration, workload type, image reference type, image
digest, restart value, top-level volume, and typed mount.

The QOS attestation document MUST bind the complete Manifest V3 hash.

The normal QOS attestation does not prove that a workload is currently
running. In attested mode, it binds the approved configuration to the measured
QOS environment. Debug mode has the zero-PCR limitation described above.

## Compatibility

| QOS implementation | V1/V2 | V3 |
| --- | --- | --- |
| New V3-capable QOS | Accepts existing schemas | Accepts supported fields and types; rejects unknown fields and types |
| Pre-V3 QOS | Existing support unchanged | Unsupported |

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
