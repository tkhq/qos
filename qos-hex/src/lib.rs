//! Utilities for encoding and decoding hex strings.
// Inspired by https://play.rust-lang.org/?version=stable&mode=debug&edition=2015&gist=e241493d100ecaadac3c99f37d0f766f

use std::num::ParseIntError;

const MEGABYTE: usize = 1024 * 1024;
const GIGABYTE: usize = 1024 * MEGABYTE;
const STR_MAX_LENGTH: usize = GIGABYTE;

/// 255 ordered pairs of characters. The first pair decodes to 0 and the last
/// pair decodes to 255.
const HEX_BYTES: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                         404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
                         606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                         c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                         e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/// Error type for decoding hex strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
	/// Could not decode the input because it was an odd length.
	OddLength,
	/// Error trying to parse hex characters to a u8.
	ParseInt(ParseIntError),
	/// The input could not be decoded because it exceeds the max allowed
	/// length.
	// See `STR_MAX_LENGTH` for the max length.
	ExceedsMaxLength,
}

impl From<ParseIntError> for HexError {
	fn from(e: ParseIntError) -> Self {
		HexError::ParseInt(e)
	}
}

/// Decode bytes from a hex encoded string.
///
/// This handles both strings prefixed with `0x` and non-prefixed strings.
///
/// # Errors
///
/// - if the input is an odd length
/// - if a character is invalid hex
/// - if the input is too long.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
	let s = if &s[..2] == "0x" { &s[2..] } else { s };
	let str_byte_len = s.len();

	let is_even_len = str_byte_len % 2 == 0;
	let is_lt_max_len = str_byte_len < STR_MAX_LENGTH;
	match (is_even_len, is_lt_max_len) {
		(true, true) => (0..str_byte_len)
			.step_by(2)
			.map(|i| {
				u8::from_str_radix(&s[i..i + 2], 16)
					.map_err(std::convert::Into::into)
			})
			.collect(),
		(true, false) | (false, false) => Err(HexError::ExceedsMaxLength),
		(false, true) => Err(HexError::OddLength),
	}
}

/// Encode a byte slice to hex string. Always encodes with lowercase characters.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
	bytes
		.iter()
		.map(|&b| {
			let i = 2 * b as usize;
			HEX_BYTES.get(i..i + 2).expect(
				"HEX_BYTES represents 00..=ff, and thus any valid u8. qed.",
			)
		})
		.collect()
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn encode_and_decode_work() {
		let decoded = vec![0, 0, 0, 0];
		let encoded = "00000000";
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);

		let decoded = vec![255, 0, 255];
		let encoded = "ff00ff";
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);

		let decoded: Vec<_> = (0..=255u8).collect();
		let encoded = HEX_BYTES;
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);

		let decoded = vec![31, 52, 228, 109, 140, 170, 124, 94];
		let encoded = "1f34e46d8caa7c5e";
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);

		// Handles `0x` prefix and mixed casing
		let decoded = vec![
			0, 0, 0, 0, 33, 154, 181, 64, 53, 108, 187, 131, 156, 190, 5, 48,
			61, 119, 5, 250,
		];
		let address = "0x00000000219ab540356cBB839Cbe05303d7705Fa";
		let mut encoded = address[2..].to_string();
		encoded.make_ascii_lowercase();
		assert_eq!(encode(&decoded), &encoded[..]);
		assert_eq!(decode(address).unwrap(), decoded);

		// Rejects invalid hex characters
		let invalid = "a1b2fh";
		let is_err = matches!(
			decode(invalid),
			Err(HexError::ParseInt(ParseIntError { .. }))
		);
		assert!(is_err);

		// Reject odd length string
		let invalid = "fff";
		assert_eq!(decode(invalid), Err(HexError::OddLength));
	}

	#[test]
	#[ignore]
	fn decode_respects_max_len() {
		// Accepts a string of exactly the correct length
		let valid =
			(0..STR_MAX_LENGTH - 2).map(|_| "f").collect::<Vec<_>>().join("");
		assert!(decode(&valid).is_ok());

		// Rejects a string that is over length by just 1 char.
		let invalid = format!("{valid}ff");
		assert_eq!(decode(&invalid), Err(HexError::ExceedsMaxLength));
	}
}
