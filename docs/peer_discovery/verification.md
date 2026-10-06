# Peer Attestation Verification

Status: Draft target specification

## Initial proof transport

The guest MUST send the existing `LiveAttestationDocRequest` protocol message
to the candidate host using `POST /qos/message` and QOS JSON wire encoding.

The guest MUST require a `LiveAttestationDocResponse` containing both an
`NsmResponse::Attestation` document and a manifest envelope. A protocol error,
missing envelope, or other NSM response MUST fail the contact.

The initial implementation MUST reuse the QOS Host's existing Axum server.
It does not require a new HTTP server inside the enclave.

Each contact sends a new attestation request. The existing QOS attestation
service generates NSM evidence for each request. The guest MUST enforce
freshness on the response; it does not rely on host claims about caching.

`POST /qos/message` is the initial transport and MAY change in a later
specification. The initial request uses the existing nonce-free attestation
flow; discovery does not introduce a challenge message or TLS handshake.

## Evidence verification

Before publishing a peer, the guest MUST:

1. Verify the attestation certificate chain against a locally trusted Nitro
   root and verify the COSE signature. Validate certificates at the current
   local NSM time, converted from milliseconds to seconds.
2. Require a signed timestamp no more than 10 minutes old or 1 minute ahead
   of local NSM time.
3. Parse the manifest envelope using its declared schema and calculate the
   manifest hash using that schema's existing QOS rules.
4. Require the attestation `user_data` to equal that manifest hash and verify
   PCR0 through PCR3 against the manifest. Require every release-pinned PCR
   index; the initial implementation requires indexes 0 through 31.
5. Parse the attested public key as the existing QOS `P256Public` encoding:
   `encrypt_public || sign_public`, two valid uncompressed SEC1 P-256 points
   totaling 130 bytes. The guest MUST reject a malformed key.
6. Verify the live/app commitment in PCR17 against the manifest hash and
   attested live ephemeral public key. A setup/boot proof is insufficient for
   this peer list.

These checks use the peer's reported manifest. The local manifest is used
only for the relationship comparison below.

The guest MUST reject an unsupported evidence or manifest format. It MUST use
the existing nonce policy: the attestation nonce MUST be absent. It MUST NOT
treat an HTTP success as successful verification.

Time checks and `lastContactedAt` MUST use the local NSM time source, independent
of host advice. Retry deadlines, refresh intervals, and stale deadlines MUST
use a monotonic clock.

## Manifest relationship

Every published record MUST contain exactly one of these relationships:

| Value | Meaning |
| --- | --- |
| `sameManifest` | The verified manifest hash equals the local manifest hash. |
| `otherManifest` | The verified manifest hash differs from the local manifest hash. |

The guest MUST calculate the relationship. It MUST NOT accept a classification
provided by the host or candidate.

The API MUST represent both relationships. Both require valid attestation.
Neither label grants application trust. Consumers choose their own policy
using the manifest hash and attested public key, and can fetch evidence.

Discovery MUST NOT apply manifest approval or key-forwarding admission checks.
Differences in namespace, quorum key, Manifest Set, or manifest nonce do not
prevent publication of a peer with valid attestation.

## Identity and freshness

The peer ID MUST be the lowercase hexadecimal SHA-256 hash of the exact public
key bytes in the verified live attestation. It identifies one enclave live-key
instance. Two enclaves using the same manifest have separate peer IDs.

The guest MUST exclude its own live-key identity from the published peer list.
It MUST compare the verified public key with its local live public key, rather
than infer self-identity from an IP address. A verified self response succeeds
for contact scheduling but MUST NOT create a peer file.

The initial contract assumes each live-key identity is advertised at one
candidate address. Reusing a live key across enclave instances or advertising
the same identity through multiple candidate addresses is outside scope.

For a published peer, a contact MUST have a signed attestation timestamp
strictly newer than its last accepted timestamp before it updates the record
or resets retry backoff. Replayed evidence MUST NOT advance `lastContactedAt`.
Changes to host advice do not remove this peer or its freshness state.

## Existing implementation references

- [Protocol messages](../../src/qos_core/src/protocol/msg.rs) define the request
  and response.
- [Attestation service](../../src/qos_core/src/protocol/services/attestation.rs)
  generates a document with the manifest hash, current public key, and no nonce.
- [Nitro verification](../../src/qos_nsm/src/nitro/mod.rs) provides certificate,
  signature, manifest, and live-commitment verification.
- [QOS Host](../../src/qos_host/src/host.rs) forwards `/qos/message` requests;
  its state does not contain a proof cache.
- [Nitro attestation format](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
  defines the signed timestamp in milliseconds since the Unix epoch.

Discovery reuses the attestation verifier and adds the timestamp bounds
defined above. It does not reuse key forwarding's peer admission rules.
