# Peer Discovery Configuration

Status: Draft target specification

## Manifest opt-in

Manifest V2 and later manifest versions MUST support an optional top-level
`peerDiscovery` object. An object enables discovery. An absent or `null` field
MUST disable discovery and MUST preserve existing boot behavior, following QOS
JSON's unset-field rules. Manifest V0 and V1 do not support this feature.

The manifest hash MUST cover the complete peer discovery configuration.

The guest MUST reject invalid discovery configuration when validating the
manifest. These checks cover the configuration schema, refresh interval, and
egress support defined below.

## Configuration schema

The `peerDiscovery` object has one optional field:

| Field | Encoding | Default | Meaning |
| --- | --- | --- | --- |
| `refreshIntervalSeconds` | Base-10 integer string | `600` | Delay after a successful contact before its next refresh. `0` disables periodic refresh. |

An empty object enables discovery with the default interval:

```json
"peerDiscovery": {}
```

Explicit configuration has this form:

```json
"peerDiscovery": {
  "refreshIntervalSeconds": "600"
}
```

These are fragments of the signed manifest. The field MUST be an unsigned
integer. The object MUST reject unknown fields. An omitted interval MUST remain
omitted during serialization and hashing; QOS applies its default at runtime.

When nonzero, the refresh interval MUST be less than the 30-minute stale
timeout: valid values are `1` through `1799` seconds. QOS MUST reject a manifest
with a nonzero interval outside that range.

Disabling periodic refresh MUST NOT disable initial contacts or retries of
failed candidates. It disables age-based removal of published records.

## Fixed runtime settings

The following values are QOS runtime settings, not additional manifest fields:

| Setting | Value |
| --- | --- |
| Maximum attestation age at verification | 10 minutes |
| Maximum attestation timestamp ahead of local NSM time | 1 minute |
| Stale peer timeout | 30 minutes after the last successful contact, when periodic refresh is enabled |
| HTTP request timeout | 30 seconds for the complete connection, request, and response |
| Retry base delay | 30 seconds |
| Retry delay cap | 10 minutes |
| Retry jitter | Uniform random delay from zero through the current backoff limit |
| Maximum concurrent contacts | 32 |
| Maximum suggested addresses per advice list | 1,000 |
| Maximum published peers | 1,000 |

The longer refresh interval reduces background traffic. The age bound permits
delayed evidence, while every accepted refresh still requires an increasing
signed timestamp. The maximum evidence age plus the allowed future clock skew
MUST be less than the stale timeout. The concurrency limit bounds simultaneous
network and verification work. The candidate and peer count limits are
hardcoded and are not manifest settings.

RAM sizing is the deployment's responsibility. Per-peer memory accounting and
additional memory budgets are outside the initial feature's scope.

## Egress requirement

QOS MUST reject a manifest that enables peer discovery when either the QOS
build lacks egress support or the manifest does not enable egress.

Discovery MUST use the existing egress path. Enabling discovery MUST NOT
implicitly grant another network path.

For Manifest V2, approved egress requires a `client` entry in
`pivot.bridgeConfig`. Later manifest versions MUST require their approved
egress configuration as well.

## Address families

The initial worker MUST contact IPv4 addresses only. A candidate snapshot
containing an IPv6 address MUST be rejected with a `ProtocolErrorResponse`
without changing the previously accepted snapshot.

Candidate and record address types MUST use `IpAddr` or an equivalent type
that represents both IPv4 and IPv6. Record readers MUST parse both families.
Later IPv6 networking support MAY accept IPv6 candidates and publish IPv6
contact addresses using the existing protocol and peer record versions.

## Guest interface availability

When discovery is enabled, QOS MUST create the empty `/run/qos/peers/`
directory before it starts the pivot. Boot MUST NOT wait for a peer to become
reachable. An empty directory means that no peers are currently published.

When discovery is disabled, QOS MUST NOT create the directory or start the
discovery worker.

The worker and its directory belong to the guest QOS runtime. A pivot restart
MUST NOT clear the list or restart discovery. An enclave restart begins with
an empty list.

## Manifest compatibility

An implementation MUST reject an enabled configuration it does not support.
It MUST NOT silently ignore approved discovery settings.

The feature MUST preserve existing manifest hashes and approvals when its
configuration is absent. It MUST use the existing schema-specific manifest
hashing rules, including [QOS canonical JSON](../../src/qos_json/SPEC.md) for
JSON manifests.

Adding this optional field extends Manifest V2 without changing its `version`
value. Later manifest versions MUST retain this configuration and its absent
behavior.

Existing binaries that do not support discovery reject a V2 manifest containing
`peerDiscovery`, because the V2 schema rejects unknown fields. Upgraded binaries
MUST continue to accept earlier V2 manifests with unchanged hashes and
approvals.
