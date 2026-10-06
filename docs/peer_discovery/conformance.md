# Peer Discovery Conformance

Status: Draft target specification

An implementation conforms when it satisfies every document linked from the
[Peer Discovery](README.md) overview. The following checks define required
behavior; they are not claims about the current implementation.

## Configuration and lifecycle

- Absent configuration preserves existing boot behavior and creates no peer
  directory or worker.
- A `null` configuration has the same behavior and manifest hash as an absent
  configuration under QOS JSON's unset-field rules.
- Manifest V2 and later versions support the optional object; `{}` enables a
  10-minute refresh and `refreshIntervalSeconds: "0"` disables periodic refresh.
- Nonzero refresh intervals must be less than the 30-minute stale timeout;
  intervals of 1800 seconds or more are rejected.
- Earlier V2 manifests retain their hashes and approvals under the updated
  schema.
- Enabled discovery is rejected without build support or approved egress.
- Manifest validation rejects invalid discovery settings using the schema,
  interval, and egress checks.
- Discovery settings affect the approved manifest hash.
- The empty directory exists before pivot startup; unavailable peers do not
  delay boot.
- Maintenance continues with no application requests or file reads.
- A pivot restart preserves maintenance and records; an enclave restart
  starts with an empty directory.

## Evidence and metadata

- Initial retrieval uses `POST /qos/message` with the existing live attestation
  request and requires both evidence and envelope.
- Successful refreshes of published peers require increasing signed timestamps.
- An invalid signature, untrusted certificate root, timestamp outside the
  configured bounds, mismatched manifest hash, mismatched PCR, malformed live
  key, or setup proof does not publish a peer.
- Verification uses local NSM time for certificate validity, requires the
  release-pinned PCR range, validates the complete 130-byte QOS public key, and
  rejects an attestation nonce.
- The verifier uses its local Nitro root and computes the peer ID and manifest
  relationship from validated metadata.
- Same-manifest and different-manifest peers are labeled `sameManifest` and
  `otherManifest` by hash comparison. These values do not express approval.
- Valid attestation can publish peers with different namespaces, quorum keys,
  Manifest Sets, or manifest nonces. Discovery requires no manifest approvals.
- Evidence up to 10 minutes old or 1 minute ahead of local NSM time is
  accepted when all other checks pass; evidence outside those bounds is rejected.
- Changing advice does not remove a published peer or reset its accepted
  timestamp. Repeated evidence does not advance its contact time.
- Different live keys under one manifest produce different peer files.
- A verified response carrying the local live public key creates no peer file.
  It resets contact backoff and follows optional refresh scheduling instead of
  retrying as a failed contact.

## Refresh and retry

- A successful remote contact publishes the latest extracted metadata and contact
  time, resets backoff, and schedules optional refresh.
- A failed published contact retains the record and schedules retry without
  advancing contact time or extending the stale deadline.
- With periodic refresh enabled, 30 minutes without success removes the
  published record. Removal proceeds even when all contact slots are occupied.
  A still-suggested address keeps retrying and a fresh success republishes its
  file. Otherwise, scheduled contacts stop; an in-progress contact can finish.
- Consecutive failures double the backoff limit from 30 seconds to a 10-minute
  cap, sample full jitter within that limit, and keep retrying after the cap.
- Duplicate host advice does not reset backoff or duplicate scheduled work.
- Disabling periodic refresh disables stale removal and still permits failed
  candidates to retry.
- Omitting a known peer's address from advice does not remove its record or
  stop optional refreshes and retries.
- Changing the live identity at an address replaces the peer association and
  removes the old file. A change to the local identity removes the old file
  without publishing self.
- Worker contacts respect the 30-second HTTP timeout, 32-contact concurrency
  bound, and one-contact-per-candidate rule. Network I/O does not hold the
  control protocol's state lock.
- Each advice list contains at most 1,000 suggested addresses, and the runtime
  publishes at most 1,000 peer identities. At capacity, existing records can
  update while new identities remain unpublished until a slot is available.

## Publication and consumption

- Files contain all version 1 metadata fields and omit full attestation
  documents and manifest envelopes.
- Consumers can request and verify their own evidence through the recorded
  endpoint; file reads do not fetch evidence.
- Publishing one changed peer does not rewrite unrelated peer files.
- Concurrent reads see complete records during replacement.
- Enumerators ignore temporary files and tolerate a record removed before
  open; enumeration is not asserted to be a global snapshot.
- The reference reader performs no networking and is not required for direct
  file consumption.
- Unsupported record versions are rejected; compatible additive fields can
  be ignored.
- Initial publication uses IPv4 addresses; the record schema and reference
  reader accept both IPv4 and IPv6 strings without changing the version.

## Candidate advice

- The new JSON request and unit response use the existing QOS control path.
- Existing protocol message and error Borsh numbers and encodings remain
  unchanged by appending the new variants. A Borsh discovery request is rejected
  before its handler runs. `to_borsh_wire` rejects new discovery requests and
  responses; discovery-only payload types need no working Borsh encoding.
- Invalid or disabled advice leaves the previous candidate snapshot unchanged.
- Advice is accepted when discovery is enabled and kept in guest RAM.
  The worker can use advice accepted before it starts. Advice is not persisted.
- A snapshot with more than 1,000 distinct IP/port pairs is rejected without
  truncation or changes to the previous snapshot. Duplicate pairs do not count
  toward the limit more than once.
- IPv6 has a valid schema representation but is rejected by the initial worker
  without changing the previous snapshot. IPv6 support requires no new message
  variant or address representation.
- Each accepted request replaces the suggestions; an empty list clears those
  suggestions without removing known peers or cancelling in-progress contacts.
- Duplicate pairs and reordered lists preserve deadlines, associations, and
  retry state and do not cause peer file rewrites.
- New suggestions receive initial contacts. Omitted addresses with no known
  peer stop receiving new attempts, but in-progress contacts finish normally.
- A valid response publishes under the usual rules even if newer advice omits
  its address. Publication requires no membership check against current advice.
- The latest accepted list supplies current suggestions. Its acknowledgement
  does not wait for network verification or promise completed file publication.
