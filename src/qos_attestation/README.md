# qos_attestation

Self-attestation for QuorumOS pivots, with optional caching for serving boot
proofs without an NSM request per response.

See the API documentation in [inputs.rs](src/inputs.rs),
[verify.rs](src/verify.rs), and [cache.rs](src/cache.rs) for usage and contracts.

## Verification

Use `NsmProviderExt::attest_and_verify` for a local self-check, or
`VerifiedAttestation::verify` to verify supplied bytes against a trusted root
and expected boot inputs. Verification requires the PCR17 and PCR18
commitments written by QOS 0.15.0 onward.

Verification checks certificate validity at the document's issuance timestamp.
Clients must also enforce current-time validity and freshness requirements;
receiving a cached response does not establish that it was freshly attested.

## Optional cache

Enable the `cache` feature. With your NSM provider, manifest envelope, and live
key loaded at boot, start the cache in a Tokio runtime:

```rust, norun
use std::sync::Arc;
use qos_attestation::cache::AttestationCache;

let (cache, refresh_task) = AttestationCache::start(
    Arc::new(nsm),
    envelope.manifest_hash(),
    live_key.public_key(),
).await?;
```

Keep `cache` in application state. In a request handler:

```rust, norun
let document = cache.latest().ok_or("attestation unavailable")?;
let cose_bytes: &[u8] = &document;
// Include these bytes with the retained manifest in the boot-proof response.
```

Supervise `refresh_task`: treat startup failure or task termination
as fatal, and abort the task on shutdown. The application must handle periods
when no unexpired document is available. See [cache.rs](src/cache.rs) for the
failure and panic contracts.

The cache trusts the local NSM and does not verify signatures or bindings.
Clients must verify boot proofs. Use the NSM directly when a request needs a
fresh or nonce-bound attestation. QEMU's placeholder certificates cannot be
used with this cache.

Boot-proof manifests are public, including pivot arguments and environment
variables. Keep secrets out of them.
