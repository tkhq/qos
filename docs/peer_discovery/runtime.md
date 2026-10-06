# Peer Discovery Runtime

Status: Draft target specification

## Candidate advice

The host supplies candidate IP addresses and ports through the QOS control
connection. Candidate advice MUST be treated as untrusted input.

The guest MUST accept advice only when discovery is enabled. Receiving advice
MUST NOT publish a peer before verification succeeds.

The host MUST use the advice message defined in
[Candidate advice](control_protocol.md). Duplicate advice for a retained
candidate MUST NOT reset its retry backoff or create duplicate scheduled work.

## Worker lifecycle

QOS MUST start one guest discovery worker after the local live-key transition
and egress setup. This worker MUST be the only publisher of peer files.

The worker uses the in-memory address list supplied by the control handler,
as defined in [Handler and worker](control_protocol.md#handler-and-worker).

The worker MUST schedule initial contacts, periodic refreshes and stale removal
when enabled, and retries. It MUST NOT require a pivot request, directory read,
or SDK call to make progress.

Outbound requests MUST run outside the QOS control-message handler and its
protocol-state lock. The worker MUST allow at most 32 concurrent contacts,
including verification, and at most one outstanding contact per candidate.
Each HTTP exchange MUST have a 30-second timeout covering connection, request,
and response together.

Advice updates MUST wake the worker without waiting for a refresh interval.

QOS MUST keep the worker running while the pivot runs or restarts.

## Successful contact

A contact succeeds only after all [verification](verification.md) requirements
pass. For a remote live-key identity, the guest MUST publish the extracted
public key, manifest hash, signed attestation timestamp, contact address,
relationship, and successful contact time. It MUST NOT store the full proof or
envelope in the file. A verified self response MUST NOT publish a file and
follows the same successful-contact scheduling rules below.

On success, the worker MUST reset the candidate's retry backoff. If periodic
refresh is enabled, it MUST schedule the next refresh from that successful
contact. The interval defaults to 10 minutes and follows the signed
`refreshIntervalSeconds` value when present.

For remote peers, each newly accepted attestation advances the recorded
attestation timestamp and contact time, so it requires replacement of that
peer's file. A timer tick without a record change MUST NOT rewrite unrelated
peer files.

Changes to host advice MUST NOT invalidate a contact result. A successful
contact can publish a peer even if its address is no longer suggested.

When the same address verifies a new live-key identity, the guest MUST remove
the old peer's file. It MUST publish the new peer ID unless that identity is
local. One verified identity MUST have at most one peer file. Each identity is
expected at one candidate address, as defined in
[Identity and freshness](verification.md#identity-and-freshness).
Maintaining alternate routes or providing failover between addresses for the
same identity is outside scope.

## Failure and retry

A timeout, network failure, or rejected attestation MUST count as a failed
contact. A failed contact MUST NOT immediately remove a published record or
extend its stale deadline. The worker MUST retry while
the address is suggested or has a published peer. Host advice changes MUST
NOT stop retries or optional refreshes for a published peer.

Retries MUST continue with capped exponential backoff and full jitter:

```text
limit(k) = min(600 seconds, 30 seconds * 2^k)
delay(k) = uniform_random(0, limit(k))
```

`k` is zero for the first retry and increases after each consecutive failed
attempt. The limits are 30, 60, 120, 240, 480, then 600 seconds. The actual delay
is sampled independently for each retry. It starts when the failed attempt
ends. Reaching the cap MUST NOT stop retries. A successful contact resets `k`.

Random delays spread retries across enclaves, following the full-jitter model
in [AWS retry guidance](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/).

Failures MUST NOT advance `lastContactedAt`. An unchanged or older signed
attestation MUST NOT count as a fresh successful contact.

With periodic refresh disabled, successful records remain observations of
their last successful contact and MUST NOT be removed by the stale timer.
Consumers can evaluate their age from the record. Failed initial contacts
still retry.

## Stale removal

With periodic refresh enabled, the worker MUST remove a published peer's file
after 30 minutes without a successful contact. Each successful contact resets
this deadline. Failed contacts and host advice MUST NOT reset it.

Stale removal MUST run independently of available contact slots. An overdue
refresh waiting for a slot MUST NOT postpone removal. If the address is still
suggested, contacts continue after removal and a fresh successful contact
publishes the peer again. Otherwise, removal ends scheduled contacts to that
address; a contact already in progress can still succeed.

## Resource use

Record changes MUST update only the relevant peer file.

The initial runtime MUST accept at most 1,000 suggested addresses per list and
publish at most 1,000 peer identities. These limits are hardcoded. Oversized
advice is rejected as defined in [Candidate advice](control_protocol.md).
When the peer list is full, contacts can update existing records, but new
identities remain unpublished until a slot is available.

Files contain only metadata; full evidence and envelopes are transient
verification input. RAM sizing is the deployment's responsibility. The initial
feature does not require per-peer memory accounting or additional memory
budgets and does not claim measured throughput.
