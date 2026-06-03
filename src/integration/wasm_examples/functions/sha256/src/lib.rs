use qos_wasm_sdk_macros::qos_function;
use sha2::{Digest, Sha256};

#[qos_function]
pub fn sha256_digest(input: Vec<u8>) -> Vec<u8> {
	Sha256::digest(&input).to_vec()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hashes_bytes_as_plain_rust() {
		let digest = sha256_digest(b"hello".to_vec());
		assert_eq!(digest.len(), 32);
		assert_eq!(
			qos_hex_for_test(&digest),
			"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
		);
	}

	fn qos_hex_for_test(bytes: &[u8]) -> String {
		const HEX: &[u8; 16] = b"0123456789abcdef";
		let mut out = String::with_capacity(bytes.len() * 2);
		for byte in bytes {
			out.push(HEX[(byte >> 4) as usize] as char);
			out.push(HEX[(byte & 0x0f) as usize] as char);
		}
		out
	}
}
