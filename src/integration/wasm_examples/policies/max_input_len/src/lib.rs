use qos_wasm_sdk::{Decision, PolicyContext};
use qos_wasm_sdk_macros::qos_policy;

const MAX_INPUT_LEN: usize = 1024;

#[qos_policy]
pub fn max_input_len(context: PolicyContext) -> Decision {
	if context.input.len() <= MAX_INPUT_LEN {
		Decision::allow()
	} else {
		Decision::deny(format!("input exceeds {MAX_INPUT_LEN} bytes"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn context_with_input(input: Vec<u8>) -> PolicyContext {
		PolicyContext {
			function_hash: [7; 32],
			function_wasm: b"\0asmexample".to_vec(),
			input_hash: [9; 32],
			input,
		}
	}

	#[test]
	fn allows_small_inputs_without_wasm_runtime() {
		assert!(
			max_input_len(context_with_input(b"hello".to_vec())).is_allowed()
		);
	}

	#[test]
	fn denies_large_inputs_without_wasm_runtime() {
		let decision = max_input_len(context_with_input(vec![0; 1025]));
		assert_eq!(decision, Decision::deny("input exceeds 1024 bytes"));
	}
}
