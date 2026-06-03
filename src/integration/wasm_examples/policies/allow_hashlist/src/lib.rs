use qos_wasm_sdk::{Decision, PolicyContext};
use qos_wasm_sdk_macros::qos_policy;

const ALLOWED_FUNCTION_HASHES: [[u8; 32]; 1] = [[42; 32]];

#[qos_policy]
pub fn allow_hashlist(context: PolicyContext) -> Decision {
	if ALLOWED_FUNCTION_HASHES.contains(&context.function_hash) {
		Decision::allow()
	} else {
		Decision::deny("function hash is not approved by this policy")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn context(function_hash: [u8; 32]) -> PolicyContext {
		PolicyContext {
			function_hash,
			function_wasm: b"\0asmexample".to_vec(),
			input_hash: [1; 32],
			input: b"hello".to_vec(),
		}
	}

	#[test]
	fn allows_hashlisted_function_without_wasm_runtime() {
		assert!(allow_hashlist(context([42; 32])).is_allowed());
	}

	#[test]
	fn denies_unknown_function_without_wasm_runtime() {
		assert_eq!(
			allow_hashlist(context([9; 32])),
			Decision::deny("function hash is not approved by this policy")
		);
	}
}
