# Peer Discovery

QOS can give a pivot a list of peer IP addresses supplied by the host. The list
is untrusted advice. The guest checks nothing about the peers and never
contacts them.

## Configuration

Manifest V2 has an optional `peerDiscovery` object:

```json
"peerDiscovery": {"enabled": true}
```

Discovery is disabled when the field is absent or `enabled` is `false`.
Manifest V0 and V1 do not support it. `qos_client generate-manifest
--use-manifest-version 2 --peer-discovery true` writes the field, and manifest
approval displays the setting.

## Control messages

The host sends these over the existing control channel, for example through
QOS Host's `POST /qos/message`:

```json
{"addPeersRequest": {"ips": ["192.0.2.42", "2001:db8::1"]}}
{"removePeersRequest": {"ips": ["192.0.2.42"]}}
```

Adding a listed address or removing an unlisted one changes nothing. The guest
responds `"addPeersResponse"` or `"removePeersResponse"` after the peer file is
updated. On failure it returns a `ProtocolErrorResponse` and the list is
unchanged. The guest accepts these messages only after the quorum key is
provisioned and only if the manifest enables discovery. They never change the
protocol phase.

The guest does not expire or limit entries. Keeping the list current is up to
the host.

## Peer file

`/run/qos/untrusted_host_provided_peers` holds one IP address per line, sorted,
with no other content:

```text
192.0.2.42
2001:db8::1
```

The file appears on the first update. Each update replaces it by rename, so
readers always see a complete list. It lives on tmpfs: pivot restarts keep it,
and an enclave restart clears it. Pivots must treat it as read-only.

The list has no ports. The application decides how to reach an address.

## Trust

An entry means only that the host asked for it. Before trusting a listed peer,
a pivot must verify the peer itself. For example, it can fetch the peer's live
attestation over the application's own protocol, check it against its own
policy, and then authenticate later messages with the attested key.

The host can already deny service, so controlling the list gives it no new
power.

## Rejected alternative: guest-verified peers

We considered having the guest verify each peer's attestation and list only
peers in the same application. "Same application" is a policy: the same
Manifest Set, quorum key, QOS measurements, or some combination, and each of
these changes across upgrades. Verification also would not authenticate the
address or later messages, so pivots would still have to verify peers
themselves. We left verification to them.
