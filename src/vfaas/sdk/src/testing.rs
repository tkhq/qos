//! Test helpers available only on non-WASM targets.
//!
//! The point of this module: a program or policy author should be able to
//! run `cargo test` against their logic with no WASM toolchain, no
//! wasmtime, no enclave, no socket. They write a plain Rust function
//! annotated with `#[program]` or `#[policy]`, then call that function
//! directly in `#[test]` blocks using `mock_context()` to manufacture the
//! `Context` argument.

use crate::Context;

/// Build a `Context` suitable for use in unit tests on non-WASM targets.
#[must_use]
pub fn mock_context() -> Context {
	Context::__new_internal()
}
