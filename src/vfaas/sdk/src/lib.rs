//! vfaas SDK: write a program or policy as one typed Rust function.
//!
//! ```ignore
//! use vfaas_sdk::{policy, Context, Decision, PolicyRequest};
//!
//! #[policy]
//! fn evaluate(_ctx: &Context, req: PolicyRequest) -> Decision {
//!     if req.input.len() > 1024 {
//!         Decision::Deny("input too large".into())
//!     } else {
//!         Decision::Allow
//!     }
//! }
//! ```
//!
//! `#[program]` and `#[policy]` emit the WASM ABI wrapper only under
//! `cfg(target_arch = "wasm32")`. Under any other target the user function
//! is left untouched, so `cargo test` runs it as a normal Rust function with
//! no WASM toolchain in the loop.
//!
//! The wire types (`Decision`, `PolicyRequest`, hash newtypes) are
//! re-exported from the `vfaas-abi` crate — the same crate the host
//! compiles against — so the guest and host layouts cannot drift.

#![warn(missing_docs)]

pub use vfaas_sdk_macros::{policy, program};

pub use borsh;

pub use vfaas_abi::{Decision, PolicyHash, PolicyRequest, ProgramHash};

mod context;

#[doc(hidden)]
pub mod rt;

#[cfg(not(target_arch = "wasm32"))]
pub mod testing;

pub use context::Context;
