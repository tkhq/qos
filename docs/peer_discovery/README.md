# Peer Discovery

Status: Draft target specification

QOS peer discovery maintains an enclave-local list of peers whose attestation
the guest has verified. The host supplies untrusted candidate addresses. A
guest worker contacts those addresses and publishes one file per verified peer
under `/run/qos/peers/`. Pivots can read these files directly in any language.

Peer discovery requires egress and manifest opt-in, available in Manifest V2
and later versions. The worker runs independently of application requests.
Periodic refresh is optional; failed contacts use exponential backoff.

This directory defines the target contract. The peer discovery worker,
manifest configuration, host advice messages, and file publisher are not yet
implemented.

## Normative language

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative
when they use uppercase letters.

## Advice and attestation

Host input is untrusted, nondeterministic routing advice. Discovery's security
guarantee is that the guest validates attestation before publishing a peer.
The contact address, advice order, completeness, and availability are not
trusted. Denial of service by the host is outside the QOS security model;
advice authentication is not required.

The guest MUST verify the signed attestation and its binding to the reported
manifest and live ephemeral public key. Attestation validation does not
establish local approval of the peer's software. Manifest relationship is a
hash comparison; pivots apply their own application trust policy.

The contact address remains routing advice. The proof does not bind the HTTP
connection or IP address to the live key. A pivot authenticates an application
connection using the attested key when needed.

Discovery is an observation service. File presence records a successful
verification at `lastContactedAt`; it does not guarantee that a peer is still
reachable or that its application is healthy.

## Document map

- [Configuration](configuration.md) defines manifest opt-in and compatibility.
- [Candidate advice](control_protocol.md) defines host-to-guest messages and
  advice updates.
- [Verification](verification.md) defines proof retrieval and peer identity.
- [Runtime](runtime.md) defines host advice, scheduling, removal, and retry.
- [Peer files](peer_files.md) defines the guest-facing API and publication.
- [Conformance](conformance.md) defines the required behavior checks.

## Evolution

These files are the living specification for peer discovery. Changes to its
contract MUST update the relevant specification and conformance requirements
in the same repository as the implementation.

The initial proof transport is `POST /qos/message`. A later specification MAY
replace that transport without changing the peer file contract.

Peer file version `v1` has the meaning defined in [Peer files](peer_files.md).
An incompatible record change MUST use a new version. An additive field MUST
define its meaning when absent.

## Initial contract

Manifest V2 and later versions use the optional `peerDiscovery` object.
Discovery accepts peers whose live attestations validate. It labels their
manifest hashes `sameManifest` or `otherManifest` relative to the local
manifest. These labels do not express approval.

The guest excludes its own live public key from the peer list.

The host suggests addresses to contact. The guest verifies new addresses and
maintains known peers independently of later advice changes. Contacts already
in progress can publish valid results even if their addresses are omitted from
new advice. The initial runtime has hardcoded limits of 1,000 suggested
addresses per list and 1,000 published peers.

Initial networking supports IPv4. Address types and file readers MUST support
both IPv4 and IPv6 so IPv6 networking can be added without changing the wire
or file schemas.

Refresh defaults to 10 minutes. Evidence can be at most 10 minutes old or
1 minute ahead of local NSM time. With periodic refresh enabled, a peer becomes
stale after 30 minutes without a successful contact and its file is removed.
HTTP requests time out after 30 seconds.
Retries use a 30-second base and 10-minute cap with jitter. The worker permits
32 concurrent contacts.

Peer files contain compact metadata. They omit full attestation documents and
manifest envelopes. Consumers can obtain evidence from the contact endpoint;
a later specification MAY add evidence to the files.
