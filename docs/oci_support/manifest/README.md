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
required `type` discriminator and signed `mode` to `enclave`. V3 signs the
expected debug identity in the enclave configuration. It omits the V2 pivot
debug flag from workload values.

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
- `volumes`;
- `bridgeConfig`.

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

For `nitro`, `mode` MUST be `attested` or `debug`. The value is signed. QOS
MUST reject a missing or unsupported mode.

`mode` is the enclave's debug mode. It does for every workload of the enclave
what the Manifest V2 pivot `debugMode` flag does for the pivot, and nothing
else:

- `debug` is V2 `debugMode: true`: QOS pipes each workload's stdout and
  stderr and reprints every line, tagged with the workload's name;
- `attested` is V2 `debugMode: false`: QOS sends each workload's stdout and
  stderr to null.

The mode is enclave-wide: workload values MUST NOT contain a debug-mode
field. As the V2 flag does, the mode does not control Nitro launch, the
expected PCRs or their comparison, and it does not bypass manifest approval
or workload-content verification.

`pcr0`, `pcr1`, `pcr2`, and `pcr3` are required in both modes. Each PCR MUST
be a lowercase hexadecimal string encoding 48 bytes (96 hex characters).
Canonical JSON preserves string case. Uppercase hex would change the manifest
hash, so QOS MUST reject uppercase PCR values. The PCRs and the Nitro fields
`awsRootCertificate` and `qosCommit` retain their Manifest V2 meaning, and
approval and attestation verification compare them as for Manifest V2.

In V2, the host's `DEBUG` environment variable at enclave boot sets
`RunEnclavesArgs.debug_mode`. When `DEBUG` is true, Nitro launches a debug
enclave and makes the PCRs zero. `LOGS` selects console attachment. See
[enclave launch](../../../src/qos_enclave/src/main.rs). Reprinted workload
output, like reprinted pivot output, is visible only with `DEBUG` and `LOGS`
at enclave boot. See the
[V2 pivot schema](../../../src/qos_core/src/protocol/services/boot/manifest/v2.rs),
[reaper](../../../src/qos_core/src/reaper.rs), and
[Nitro PCR verification](../../../src/qos_nsm/src/nitro/mod.rs).

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

Each initial workload has `type` equal to `oci`. PR 824 also defines `pivot`;
this OCI-only implementation rejects it.

Each OCI workload MAY contain the tagged `mounts` list defined in
[Workload mounts](mounts.md).

## Ingress

Departure from PR 824, which has `bridgeConfig` only inside pivot workloads:
this OCI-only implementation has an optional top-level `bridgeConfig` list with
the Manifest V2 pivot `bridgeConfig` schema. Each `server` entry makes the QOS
host bridge forward its TCP `port` over VSOCK `port`, and the enclave connects
each stream to `127.0.0.1:port` inside the workloads' shared network namespace.
`client` (egress) entries are rejected as not yet supported, as are two
`server` entries with the same port. An absent or empty list means no ingress
and is omitted from the canonical encoding.

```json
"bridgeConfig": [{"type": "server", "port": 3000, "host": "0.0.0.0"}]
```

## Tagged Manifest V3 objects

New Manifest V3 objects use `type` when the object has, or can reasonably gain,
more than one semantic variant.

| Object | Initial type values |
| --- | --- |
| `enclave` | `nitro` |
| workload | `oci` (`pivot` in PR 824, not implemented here) |
| workload `image` | `ociManifest` |
| top-level volume | `tmpfs` |
| workload mount | `volume` |

Manifest V2 records that V3 reuses without a semantic change do not gain a
`type` field.

## Complete example

This example uses the existing Manifest V2 control-plane fields without
redefining their inner schemas. It uses an OCI workload, a
shared tmpfs volume, the implicit `qos` volume, and an ingress
`bridgeConfig`. Certificate and key values are
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
  "bridgeConfig": [
    {
      "type": "server",
      "port": 3000,
      "host": "0.0.0.0"
    }
  ],
  "workloads": {
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
workload type, image reference type, image
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
