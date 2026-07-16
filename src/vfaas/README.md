# vfaas — Verifiable Functions

Three claims, one demo:

1. **Shipping enclave logic becomes an artifact approval, not a deployment.**
   Today every app change is a new manifest + quorum re-sign + reboot +
   reprovision. Here, one long-lived pivot accepts new functions and policies
   under the same 2-of-3 quorum signature — the governance ceremony is the
   *only* delta. And the quorum doesn't just approve the code: it signs
   *which policy governs which program*. A program can't even register
   without a binding, and the caller can't pick the policy at request time.
2. **The authoring surface is one typed Rust function.** `cargo test`, no
   unsafe, no FFI, no enclave knowledge.
3. **Every outcome is provable.** Allowed, denied, or crashed: each execution
   returns an enclave-signed attestation binding program, policy, input, and
   result. You can audit what was *refused*, not just what ran.

None of the trust machinery is new: artifacts and bindings are approved with
the exact `ManifestSet`/`Approval` primitives QOS and TVC already use for
manifests.

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

That's the whole policy ([`examples/allow-small-input`](examples/allow-small-input/src/lib.rs)).
`PolicyRequest` also carries the program's hash — precomputed by the host, so
an allowlist policy ([`examples/allow-hashlist`](examples/allow-hashlist/src/lib.rs)) is a
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
cargo xtask approve  fee-calculator    # 2-of-3 signs the descriptor AND the
                                       #   ruleset binding it to its policy
cargo xtask register fee-calculator    # live on the running enclave — no reboot
cargo xtask invoke   fee-calculator --amount 1000000 --tier pro
```

Minus CLI plumbing, the *entire* deployment is this
([`approve`](../xtask/src/main.rs#L379) + [`register`](../xtask/src/main.rs#L508)
in the xtask):

```rust
let artifact = Artifact::new(
    ArtifactKind::Function, "fee-calculator", "0.1.0",
    &wasm, metadata, Some(2_000_000),        // fuel budget is signature-bound
);
let ruleset = Ruleset {                      // ...and so is the gating policy
    program: ProgramHash::new(artifact.wasm_hash),
    policy: PolicyHash::new(sha_256(&policy_wasm)),
};
let envelope = ArtifactEnvelope {
    artifact,
    approvals: vec![/* user1, user2 sign the descriptor */],
};
let ruleset = RulesetEnvelope {
    ruleset,
    approvals: vec![/* user1, user2 sign the binding */],
};
client.call(&VfaasMsg::RegisterArtifactRequest { envelope, wasm, ruleset }).await
// pivot: verifies 2-of-3 over descriptor and binding, compiles + caches → live
```

There is no step where anything reboots, reprovisions, or re-attests. And
invoking names *only* the program — `ExecuteRequest { program, input }` — the
pivot resolves the quorum-bound policy itself. Rotating a program to a
different policy is one more governance act:
`cargo xtask approve reverse --policy allow-hashlist && cargo xtask register reverse`.

## Run the demo

```sh
rustup target add wasm32-unknown-unknown   # once
cargo xtask demo
```

Scripts everything above end-to-end: generates governance under
`target/vfaas/governance/`, wasm blobs under `artifacts/`, signed envelopes
and rulesets under `envelopes/`; spawns the pivot; registers all four
artifacts; then invokes fee quote (allowed) and reverse (allowed), denies a
2 KiB input, and live-rotates reverse onto the hash-allowlist policy with a
fresh 2-of-3 ruleset (denied — unpinned hash) — verifying the enclave
signature on every attestation, including the denials.

---

Everything below is for readers who want to open the code.

## Who runs what — a map of the code

The pivot is ordinary host Rust in `src/integration` and is **the server: it
is the binary that runs inside the QOS enclave**. The SDK crates are what
function/policy authors depend on; their output is WASM that runs *inside
wasmtime inside that server*. The xtask is the client — the role your
service would play.

**Runs in the enclave (the server):**

| File | What it is |
|---|---|
| [`../integration/src/bin/pivot_vfaas.rs`](../integration/src/bin/pivot_vfaas.rs) | The pivot: quorum + ruleset verification at registration, module cache, policy-first execution, attestation signing |
| [`../integration/src/vfaas/governance.rs`](../integration/src/vfaas/governance.rs) | `Artifact`/`ArtifactEnvelope`, `Ruleset`/`RulesetEnvelope`, K-of-N verification (also used client-side to *create* approvals) |
| [`../integration/src/vfaas/mod.rs`](../integration/src/vfaas/mod.rs) | The `VfaasMsg` socket protocol; also the client-side `verify_execution_attestation` |

**Compiled to `wasm32-unknown-unknown`, runs inside wasmtime:**

| File | What it is |
|---|---|
| [`sdk/src/lib.rs`](sdk/src/lib.rs) | Author-facing SDK: `#[program]`, `#[policy]`, `Context`, re-exported ABI types |
| [`sdk-macros/src/lib.rs`](sdk-macros/src/lib.rs) | The attribute macros; ABI glue is emitted only under wasm32, so host `cargo test` sees plain functions |
| [`sdk/src/rt.rs`](sdk/src/rt.rs) | Guest runtime the macros wire in: provenance-tracked allocation |
| [`examples/reverse/src/lib.rs`](examples/reverse/src/lib.rs) | Smoke-test function |
| [`examples/fee-calculator/src/lib.rs`](examples/fee-calculator/src/lib.rs) | The business-logic demo function |
| [`examples/allow-small-input/src/lib.rs`](examples/allow-small-input/src/lib.rs) | Input-size policy |
| [`examples/allow-hashlist/src/lib.rs`](examples/allow-hashlist/src/lib.rs) | Hash-allowlist policy |

**Compiled by all three** (host, guest, client):

| File | What it is |
|---|---|
| [`abi/src/lib.rs`](abi/src/lib.rs) | The single shared-types crate (borsh-only): `Decision`, `PolicyRequest`, `ExecutionOutcome`, hash newtypes, attestation payload |

**Client side** ([`../xtask/src/main.rs`](../xtask/src/main.rs), the demo CLI):

- [`bootstrap`](../xtask/src/main.rs#L280) — quorum keygen + Borsh `ManifestSet` governance file
- [`approve`](../xtask/src/main.rs#L379) — the governance ceremony: 2-of-3 over the artifact descriptor and, for functions, over the program→policy ruleset
- [`register`](../xtask/src/main.rs#L508) — pushes envelopes (+ ruleset) to the running pivot
- [`invoke`](../xtask/src/main.rs#L596) — executes by program name and verifies the returned attestation
- [`demo`](../xtask/src/main.rs#L696) — the scripted three acts

The end-to-end test ([`../integration/tests/vfaas.rs`](../integration/tests/vfaas.rs))
boots the real pivot binary and drives registration rejections (including
every ruleset misuse), all three outcomes, fuel budgets, and a live policy
rotation — with hand-written WAT fixtures, so `cargo test --workspace` needs
no wasm toolchain.

## What an attestation says

`{engine_id, abi_version, program_hash, policy_hash, input_hash, outcome,
request_id}`, signed by the enclave ephemeral key. `policy_hash` is whatever
the quorum bound at registration — the attestation proves *which* policy
gated the run. `outcome` is three-state:

- `Allowed { output_hash }`
- `Denied { reason }` — the policy ran to completion and said no
- `Failed { stage, reason }` — a stage trapped or ran out of fuel; never
  disguised as a denial, so auditors can tell "policy denied" from "crashed"

## Key decisions

- **Governance reuses QOS primitives** (`ManifestSet`/`Approval`): approving an
  artifact is the same act, keys, and threshold math as approving a manifest —
  and the same primitives TVC already stores.
- **Programs and policies are quorum-bound, not caller-paired**: a `Ruleset`
  (program hash + policy hash, domain-separated signing payload) needs the
  same 2-of-3, a program cannot register without one, and the execute request
  has no policy field to abuse. Rotation = a fresh signed ruleset.
- **One shared types crate** ([`abi`](abi/src/lib.rs), borsh-only) compiled by
  host, guest, and client — wire drift is a compile error.
  `ProgramHash`/`PolicyHash` newtypes make swapped hashes a compile error too.
- **Raw Borsh wire contract**: `input` is `Borsh(T)` handed to the guest
  byte-for-byte; output is the guest's `Borsh(R)` bytes, and `output_hash`
  commits to exactly those bytes. The host never re-encodes either side.
- **Compile at registration, cache by hash**: garbage blobs fail at register
  with the registrant; per-call cost is a fresh fuel-metered `Store` +
  instantiate.

## Next steps

- Deploy `pivot_vfaas` as a TVC app — same binary, same approval primitives.
- Chain the ephemeral key to the NSM attestation document (client verification
  currently stops at the ephemeral key).
- Grow `&Context` into real capabilities (signing, time, prior decisions) —
  it's plumbed through every entry point as the reserved slot.
- Ruleset lifecycle: today a binding lives until a newer quorum-approved one
  replaces it; revocation/expiry and multi-policy bindings are open design.
- Registry persistence/eviction; today it's in-memory per deployment.
