# qos_attestation

Attestation for QuorumOS, with optional caching for serving boot
proofs without an NSM request per response.

See the API documentation in [inputs.rs](src/inputs.rs),
[verify.rs](src/verify.rs), and [cache.rs](src/cache.rs) for usage and contracts.

## Verification

Use `NsmProviderExt::attest_and_verify` for a local self-check, or
`VerifiedAttestationDocument::verify_at` to verify supplied bytes against a
trusted root and expected boot inputs. Verification requires the PCR17 and PCR18
commitments written by QOS 0.15.0 onward.

Supply a trusted verification time in Unix milliseconds to `verify_at`, normally
the current time or a deliberate historical time. Verification uses whole-second
precision and accepts issuance anywhere within the supplied time's second.
It checks certificate validity at that time and at issuance.
`attest_and_verify` uses the NSM clock.
Verification does not limit the time elapsed since issuance. Older documents
remain acceptable while their certificates satisfy the validity checks. The
cache stops serving documents before certificate expiry.

## Optional cache

Enable the `cache` feature. With your NSM provider, manifest envelope, and live
key loaded at boot, start the cache in a Tokio runtime:

```rust
use std::sync::Arc;
use qos_attestation::{AttestationInputs, cache::AttestationCache};

let (cache, refresh_task) = AttestationCache::start(
    Arc::new(nsm),
    AttestationInputs::new(live_key.public_key(), &envelope),
).await?;
```

Keep `cache` in application state. In a request handler:

```rust
let document = cache.latest().ok_or("attestation unavailable")?;
let cose_bytes: &[u8] = document.document();
// Include these bytes with the retained manifest in the boot-proof response.
```

Supervise `refresh_task`: treat startup failure or task termination
as fatal, and abort the task on shutdown. The application must handle periods
when no unexpired document is available. See [cache.rs](src/cache.rs) for the
failure and panic contracts.

The cache verifies every document against the provider root and fixed boot
inputs. Clients must verify boot proofs. Use the NSM directly when a request
needs a fresh or nonce-bound attestation. QEMU's placeholder certificates
cannot be used with this cache.

Boot-proof manifests are public, including pivot arguments and environment
variables. Keep secrets out of them.
