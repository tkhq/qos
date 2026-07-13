# vfaas — Verifiable Functions

Three claims, one demo:

1. **Shipping enclave logic becomes an artifact approval, not a deployment.**
   Today every app change is a new manifest + quorum re-sign + reboot +
   reprovision. Here, one long-lived pivot accepts new functions and policies
   under the same 2-of-3 quorum signature — the governance ceremony is the
   *only* delta.
2. **The authoring surface is one typed Rust function.** `cargo test`, no
   unsafe, no FFI, no enclave knowledge.
3. **Every outcome is provable.** Allowed, denied, or crashed: each execution
   returns an enclave-signed attestation binding program, policy, input, and
   result. You can audit what was *refused*, not just what ran.

None of the trust machinery is new: artifacts are approved with the exact
`ManifestSet`/`Approval` primitives QOS and TVC already use for manifests.

## Write a policy

```rust
use vfaas_sdk::{policy, Context, Decision, PolicyRequest};

#[policy]
pub fn evaluate(_ctx: &Context, req: PolicyRequest) -> Decision {
    if req.input.len() > 1024 {
        Decision::Deny(format!("input too large: {} bytes", req.input.len()))
    } else {
        Decision::Allow
    }
}
```

That's the whole policy ([`examples/allow-small-input`](examples/allow-small-input)).
`PolicyRequest` also carries the program's hash — precomputed by the host, so
an allowlist policy ([`examples/allow-hashlist`](examples/allow-hashlist)) is a
32-byte compare, not a multi-megabyte hash inside a fuel budget.

## Write a program

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use vfaas_sdk::{program, Context};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct FeeRequest { pub amount_cents: u64, pub tier: Tier }

#[program]
pub fn quote_fee(_ctx: &Context, req: FeeRequest) -> FeeQuote {
    // plain Rust business logic — see examples/fee-calculator
}
```

Typed Borsh in, typed Borsh out.

## Test it

```sh
cd src/vfaas/examples/fee-calculator && cargo test
```

Tests run as normal host Rust: `#[program]`/`#[policy]` only emit the WASM ABI
wrapper under `--target wasm32-unknown-unknown`. No wasm toolchain in the
author loop.

## Deploy it

Against a running pivot
(`cargo run --bin pivot_vfaas -- <usock> <governance-file> <ephemeral-key>`):

```sh
cargo xtask bootstrap                  # once: 3 quorum keys + 2-of-3 governance file
cargo xtask build    fee-calculator    # wasm32 blob
cargo xtask approve  fee-calculator    # user1 + user2 sign the descriptor
cargo xtask register fee-calculator    # live on the running enclave — no reboot
cargo xtask invoke   fee-calculator --amount 1000000 --tier pro
```

Minus CLI plumbing, the *entire* deployment is this
(`approve` + `register` in [`../xtask/src/main.rs`](../xtask/src/main.rs)):

```rust
let artifact = Artifact::new(
    ArtifactKind::Function, "fee-calculator", "0.1.0",
    &wasm, metadata, Some(2_000_000),        // fuel budget is signature-bound
);
let envelope = ArtifactEnvelope {
    artifact: artifact.clone(),
    approvals: vec![
        approve_artifact(&artifact, &user1_key, user1),  // in production: two
        approve_artifact(&artifact, &user2_key, user2),  // humans, two machines
    ],
};
client.call(&VfaasMsg::RegisterArtifactRequest { envelope, wasm }).await
// pivot: verifies 2-of-3 over the descriptor, compiles + caches the module → live
```

There is no step where anything reboots, reprovisions, or re-attests.

## Run the demo

```sh
rustup target add wasm32-unknown-unknown   # once
cargo xtask demo
```

Scripts everything above end-to-end: generates governance under
`target/vfaas/governance/`, wasm blobs under `artifacts/`, signed envelopes
under `envelopes/`; spawns the pivot; registers all four artifacts; then
invokes fee quote (allowed), reverse (allowed), a 2 KiB input (denied), and an
unpinned program hash (denied) — verifying the enclave signature on every
attestation, including the denials.

What runs where:

| Where | What |
|---|---|
| WASM (wasmtime, fueled, zero host imports) | your policy + program functions, nothing else |
| Rust host (`pivot_vfaas`) | quorum verification, module cache, hashing, attestation signing |
| Rust client (xtask / your service) | approval signing, request encoding, attestation verification |

## What an attestation says

`{engine_id, abi_version, program_hash, policy_hash, input_hash, outcome,
request_id}`, signed by the enclave ephemeral key. `outcome` is three-state:

- `Allowed { output_hash }`
- `Denied { reason }` — the policy ran to completion and said no
- `Failed { stage, reason }` — a stage trapped or ran out of fuel; never
  disguised as a denial, so auditors can tell "policy denied" from "crashed"

## Key decisions

- **Governance reuses QOS primitives** (`ManifestSet`/`Approval`): approving an
  artifact is the same act, keys, and threshold math as approving a manifest —
  and the same primitives TVC already stores.
- **One shared types crate** ([`abi`](abi), borsh-only) compiled by host, guest,
  and client — wire drift is a compile error. `ProgramHash`/`PolicyHash`
  newtypes make swapped hashes a compile error too.
- **Raw Borsh wire contract**: `input` is `Borsh(T)` handed to the guest
  byte-for-byte; output is the guest's `Borsh(R)` bytes, and `output_hash`
  commits to exactly those bytes. The host never re-encodes either side.
- **Compile at registration, cache by hash**: garbage blobs fail at register
  with the registrant; per-call cost is a fresh fuel-metered `Store` +
  instantiate.
- The integration test ([`src/integration/tests/vfaas.rs`](../integration/tests/vfaas.rs))
  drives the real pivot binary with hand-written WAT fixtures, so
  `cargo test --workspace` needs no wasm toolchain either.

## Next steps

- Deploy `pivot_vfaas` as a TVC app — same binary, same approval primitives.
- Chain the ephemeral key to the NSM attestation document (client verification
  currently stops at the ephemeral key).
- Grow `&Context` into real capabilities (signing, time, prior decisions) —
  it's plumbed through every entry point as the reserved slot.
- Registry persistence/eviction; today it's in-memory per deployment.
