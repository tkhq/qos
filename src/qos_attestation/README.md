# qos_attestation

Self-attestation for QuorumOS pivots. A pivot asks the NSM for an attestation
document over its own manifest and ephemeral key, verifies it before trusting
it, and caches it so it can serve a boot proof without an NSM call per request.

## Layers

Each layer can be used on its own.

| Layer | What it does |
|---|---|
| `inputs` | Loads the ephemeral key and manifest the document must bind to. The manifest read is bounded, and v0 manifests are rejected. |
| `verify` | `attest_self` makes one NSM call and verifies the document: the chain from `NsmProvider::attestation_root_ca_der` at the document's own timestamp, the signature, and the binding to our manifest hash, PCR0-3, the live-key commitment (PCR17), our key, and no nonce. `VerifyPolicy` sets the PCR18 check; it has no default. |
| `cache` (feature) | `AttestationCache`: single-flight refresh, a guard against piling up blocked NSM calls, expiry, refresh before expiry with backoff, input-drift detection, and `latest()`, a lock-free snapshot for request paths. |

The manifest bytes for a boot proof come from
`VersionedManifestEnvelope::boot_proof_manifest_bytes` in `qos_core`. They hash
to the attested `user_data`.

## Recommended consumer pattern

1. At startup, load the inputs, pin them with `PinnedInputs`, and call
   `get()` once before serving.
2. Serve requests from `latest()`. Never call `get()` on a request path.
3. Answer `/health` with 503 until `healthy()` is true.
4. Never return a successful response with an empty attestation document.
5. Run `spawn_watcher`, and exit if its handle resolves or if
   `wait_inputs_changed()` resolves, so the replica restarts on the new
   inputs.

Choose `ManifestOnlyCommitment::Required` on QOS 0.15.0 and later, which
write PCR18, and `NotChecked` on older releases.

## Privacy

A boot proof's manifest bytes are public. They include the pivot args and,
for v2 manifests, the pivot environment. Never put secrets there.

## Features

- `cache`: the attestation cache.
- `unsafe-verifier`: **never use in production.** Adds
  `unsafe_verify_self_attestation_skip_chain` and
  `AttestationCache::unsafe_new_skip_chain_verification`, which skip the
  certificate chain, the signature and expiry but keep every binding check.
  They exist for QEMU, whose emulated NSM doesn't sign documents. Enabling
  the feature never changes the default constructors.
