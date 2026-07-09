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

#![warn(missing_docs)]

pub use vfaas_sdk_macros::{policy, program};

pub use borsh;

mod context;
mod decision;
mod policy_request;

#[doc(hidden)]
pub mod rt;

#[cfg(not(target_arch = "wasm32"))]
pub mod testing;

pub use context::Context;
pub use decision::Decision;
pub use policy_request::PolicyRequest;
