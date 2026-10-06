# Peer File API

Status: Draft target specification

## Location and ownership

The guest-facing API is one UTF-8 JSON file per peer:

```text
/run/qos/peers/<peer-id>.json
```

`peer-id` has the meaning defined in
[Identity and freshness](verification.md#identity-and-freshness).

The files MUST reside on guest tmpfs. They are volatile runtime observations
and MUST NOT be used as recovery state after an enclave restart.

QOS is the sole writer. Pivots MUST treat the directory and its records as
read-only.

## Record version 1

Every record MUST contain these fields:

| Field | Representation | Meaning |
| --- | --- | --- |
| `version` | String `v1` | Peer record schema version. |
| `contact.ip` | IPv4 or IPv6 address string | Routing address used for the successful proof contact. |
| `contact.port` | Base-10 integer string, 1 through 65535 | Port of that QOS Host HTTP endpoint. |
| `publicKey` | Lowercase hex string | Exact live ephemeral public key bytes extracted from the verified attestation. |
| `manifestHash` | Lowercase hex string | Verified QOS manifest hash. |
| `manifestRelationship` | `sameManifest` or `otherManifest` | Hash comparison with the local manifest; neither value grants approval. |
| `attestedAt` | Base-10 integer string | Signed attestation timestamp, in milliseconds since the Unix epoch. |
| `lastContactedAt` | Base-10 integer string | Local NSM time in milliseconds since the Unix epoch at the last successful contact and verification. |

The contact port identifies the QOS Host proof endpoint. Applications determine
their own service ports.

The initial publisher MUST use IPv4 contact addresses. The schema and readers
MUST support IPv4 and IPv6 strings. Future IPv6 networking support can publish
IPv6 addresses without changing record version `v1`.

The peer ID is carried by the filename. The public key, manifest hash, and
attestation timestamp are metadata extracted by the guest. Version 1 MUST NOT
include the full attestation document or manifest envelope.

`lastContactedAt` is a local observation time. It MUST NOT substitute for the
signed attestation timestamp during evidence verification.

With periodic refresh enabled, the file remains visible through failed
contacts until the 30-minute stale timeout. Changes to host advice do not
remove it. With periodic refresh disabled, it remains an observation until
the address verifies a different identity or the enclave restarts.

The following example abbreviates the public key and manifest hash:

```json
{
  "version": "v1",
  "contact": {
    "ip": "192.0.2.42",
    "port": "8080"
  },
  "publicKey": "...",
  "manifestHash": "...",
  "manifestRelationship": "sameManifest",
  "attestedAt": "1719999999000",
  "lastContactedAt": "1720000000000"
}
```

The guest validates attestation before publishing metadata. The contact
address remains host advice, and `lastContactedAt` is a local observation.
Neither is a claim from the signed attestation.

## Obtaining attestation evidence

A consumer that needs an attestation document can fetch it from the recorded
contact endpoint using `POST /qos/message` and `LiveAttestationDocRequest`.
The response includes the document and manifest envelope. The consumer can
verify these itself and compare the resulting public key and manifest hash
with the record.

This request is the consumer's choice. Reading a peer file does not perform
it or trigger the discovery worker.

A later specification MAY add the full attestation document and manifest
envelope to peer files. The initial format keeps them out to reduce record
size and write overhead.

## Publication

There is one writer. To create or update a record, it MUST write the complete
JSON to a temporary sibling file whose name does not end in `.json`, then
rename it over the destination. Pivots MUST be able to read published files.

A reader that opens a published filename observes a complete old or new
record. Removal MUST unlink the published filename. An already open file can
remain readable after replacement or removal.

Updates to different peers are independent. Directory enumeration is not
an atomic snapshot. An identity change can expose a brief
gap or overlap while the writer removes and adds separate records.

The publisher MUST update only the changed peer.

## Readers and reference library

Consumers MAY enumerate, open, watch, or cache the files in any way they
choose. A filename can disappear between enumeration and open. Consumers MUST
ignore temporary files.

A Rust reference reader SHOULD provide the record types, default directory
path, and helpers to read a record or enumerate records. It MAY live in
`qos_core` or a small SDK crate. Its use MUST remain optional.

Reading records MUST NOT start networking, ping peers, or ask the publisher
to refresh. The file schema and publication contract MUST be sufficient to
write a reader in another language.

A reference reader MUST handle disappearance during enumeration and reject a
record version it does not understand. Version 1 readers SHOULD ignore
additional fields that do not change an existing field's meaning.
