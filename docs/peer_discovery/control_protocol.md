# Peer Candidate Advice

Status: Draft target specification

The host advises the guest about candidate IP addresses and QOS Host HTTP
ports. The guest verifies peers independently through egress.

## Messages

The QOS control protocol MUST add these variants:

```text
SetPeerCandidatesRequest {
    candidates: Vec<PeerCandidate>
}

PeerCandidate {
    ip: IpAddr,
    port: u16
}

SetPeerCandidatesResponse
```

These messages MUST use QOS JSON wire encoding. `ip` is an IPv4 or IPv6 address
string. `port` is a base-10 integer string from 1 through 65535.

Adding these messages MUST preserve every existing `ProtocolMsg` and
`ProtocolError` Borsh variant number and encoding. New variants MUST be appended
without reordering existing variants.

Discovery messages are JSON only. The wire decoder or request processor MUST
reject a discovery request identified as Borsh before invoking the discovery
handler, returning a `ProtocolErrorResponse`. `to_borsh_wire` MUST reject the
new requests and responses with `ProtocolError::InvalidMsg`.

No Borsh discovery payload format is defined. Borsh trait implementations needed
by the enclosing enum MAY return unsupported-format errors for discovery-only
payload types. Appending the variants preserves existing message numbers;
it does not enable discovery over Borsh.

The address type includes IPv6 for schema compatibility. Initial networking
supports IPv4 only; the guest MUST reject a snapshot containing IPv6 addresses.
Adding IPv6 networking MUST NOT require new message variants or another IP
representation.

The host MAY submit the request through its existing `POST /qos/message`
route. For example:

```json
{
  "setPeerCandidatesRequest": {
    "candidates": [
      {"ip": "192.0.2.42", "port": "8080"},
      {"ip": "192.0.2.43", "port": "8080"}
    ]
  }
}
```

Successful acceptance returns the unit response:

```json
"setPeerCandidatesResponse"
```

The guest MUST reject advice unless its manifest enables discovery. Invalid
input MUST return a `ProtocolErrorResponse` and preserve the previously
accepted snapshot. The existing QOS control-message size limit applies.

Each advice list MUST contain at most 1,000 distinct candidate addresses.
This limit is hardcoded. After deduplication, a snapshot exceeding the limit
MUST return a `ProtocolErrorResponse` and preserve the previously accepted
snapshot. The guest MUST NOT silently truncate the list.

## Advice updates

Each request replaces the list of suggested contact addresses. An empty list
clears those suggestions. It MUST NOT remove verified peers or cancel contacts
already in progress. Advice is not an authoritative membership list.

An address is identified by its parsed IP address and port. The guest MUST
deduplicate identical pairs. Textual spelling and list order MUST NOT affect
candidate identity or state.

The worker MUST schedule initial contacts for new addresses and preserve
existing refresh and retry schedules. Repeating or reordering the same advice
MUST NOT trigger fresh contacts, rewrite peer files, or reset backoff.

An omitted address with no known peer stops receiving new attempts. A known
peer continues optional refresh and retries at its recorded address, whether
or not that address remains in the advice. Stale removal is defined in
[Runtime](runtime.md#stale-removal).

A contact already in progress MUST complete normally. If verification
succeeds, the worker MUST use the result under the usual publication rules,
even if the host has since omitted its address. No membership check against
the latest advice is required.

## Handler and worker

The control handler validates the list, keeps it in guest RAM, and wakes the
worker. The list starts empty and is not persisted. Advice accepted before
worker startup is available when the worker starts.

The response acknowledges acceptance, not completed verification or file
publication. The handler MUST NOT wait for outbound network requests. The
most recently accepted list supplies the current suggestions. The host SHOULD
resend its list after boot or a host service restart.

## Advice and identity

The message MUST NOT carry a peer ID, manifest classification, attestation,
approval decision, or contact timestamp. Those values come from guest
verification. Advice supplies only where to make the proof request.

Candidate snapshots and verification state are guest runtime state. They do
not survive an enclave restart.
