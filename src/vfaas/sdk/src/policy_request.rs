//! Input type for policy entry points.
//!
//! The host serializes this with Borsh and passes it as the single argument
//! to the policy's `__vfaas_evaluate` WASM export. Policies can inspect both
//! the program bytes and the input bytes before allowing execution.

use borsh::{BorshDeserialize, BorshSerialize};

/// What a policy receives on every evaluation.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub struct PolicyRequest {
	/// The full bytes of the program WASM module about to run. Policies may
	/// inspect this — e.g., refuse modules over a size budget, refuse
	/// modules with WASI imports, etc.
	pub program: Vec<u8>,
	/// The input bytes the program will receive.
	pub input: Vec<u8>,
}
