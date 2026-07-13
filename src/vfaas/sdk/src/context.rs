//! Capability token passed to every vfaas entry point.
//!
//! For v1 this is an empty struct. The shape is preserved (and `&Context`
//! is in every macro-generated entrypoint signature) so future capabilities
//! — signing, time, prior-decision history — can be added without changing
//! how authors write programs and policies.

/// Capability token plumbed through every program and policy entry point.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy)]
pub struct Context {}

impl Context {
	/// Construct a fresh `Context`. Hidden from authors; the macro-generated
	/// wrapper and `testing::mock_context` are the only intended callers.
	#[doc(hidden)]
	#[must_use]
	pub fn __new_internal() -> Self {
		Self {}
	}
}
