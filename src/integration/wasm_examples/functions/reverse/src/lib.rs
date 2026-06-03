use qos_wasm_sdk_macros::qos_function;

#[qos_function]
pub fn reverse(input: Vec<u8>) -> Vec<u8> {
	input.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reverses_bytes_as_plain_rust() {
		assert_eq!(reverse(b"hello".to_vec()), b"olleh".to_vec());
	}
}
