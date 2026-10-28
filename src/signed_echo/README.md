# Signed Echo

`signed_echo` is an Axum pivot app for QOS bridge ingress. `/echo` signs a UTF-8
POST body with the quorum key; `/get_url` fetches a URL and signs its response.
Signatures cover the QOS JSON bytes in `signed_payload_json`.

## Run locally

```sh
cargo run -p signed_echo -- \
  --host 127.0.0.1 \
  --port 3000 \
  --quorum-file /path/to/qos.quorum.key

curl -X POST --data-binary 'hello' http://127.0.0.1:3000/echo
```

Defaults are `127.0.0.1:3000` and `/qos.quorum.key`.

## Cached boot proofs

Boot proofs are off by default. Inside a Nitro enclave, opt in with:

```sh
signed_echo --boot-proof nsm
```

Use `RestartPolicy::Always` in the manifest. Startup failure or refresh-task
termination exits the app so QOS can restart it.

| Route | With boot proofs enabled |
|---|---|
| `/health` | Reports readiness while an unexpired document is available. |
| `GET /boot_proof` | Returns the attestation, manifest, envelope, schema version, and live public key; byte fields are hex. |

Both return 503 when no unexpired document is available. `/echo` and
`/get_url` continue using the quorum key; this proof does not authenticate their
signatures. Publishing supports v2 manifests only; QEMU's placeholder
certificates cannot be used with this cache.

## Use the cache in another app

Enable the library feature:

```toml
qos_attestation = { workspace = true, features = ["cache"] }
```

[`BootProof::start`](src/lib.rs) loads and retains the boot inputs, then calls:

```rust,no_run
use qos_attestation::{AttestationInputs, cache::AttestationCache};

let inputs = AttestationInputs::new(ephemeral_public_key, &envelope);
let (cache, refresh_task) = AttestationCache::start(nsm, inputs).await?;
```

Request handlers borrow the cached bytes without another NSM call:

```rust,no_run
let document = cache.latest().ok_or("attestation unavailable")?;
let cose_bytes: &[u8] = document.document();
```

[`main.rs`](src/main.rs) supervises `refresh_task` alongside the HTTP server
and aborts refresh on server shutdown. Keep the matching manifest and public key
in application state. See [qos_attestation](../qos_attestation/README.md) for the
library's lifecycle and verification contracts.

The cache verifies each document against the retained boot inputs and provider
root. Clients must independently call `VerifiedAttestationDocument::verify_at`
with trusted boot inputs, a trusted root, and trusted current verification time
in Unix milliseconds. Verification imposes no maximum age; clients that need a
freshness policy must enforce it separately.
Manifest arguments and environment variables are public; keep secrets out of them.
