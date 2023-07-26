//! Utilities for encoding and decoding hex strings.
// Inspired by https://play.rust-lang.org/?version=stable&mode=debug&edition=2015&gist=e241493d100ecaadac3c99f37d0f766f

use std::{convert::Into, num::ParseIntError, string::FromUtf8Error};

const MEGABYTE: usize = 1024 * 1024;
const STR_MAX_LENGTH: usize = 256 * MEGABYTE;

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
	/// Input was of length 1, which is an odd length.
	LengthOne,
	/// Could not decode the input because it was an odd length.
	OddLength,
	// There was a char that was not valid hex i.e not in 0..=9,a..=f.
	NotHexChar,
	/// Error trying to parse hex characters to a u8.
	ParseInt(ParseIntError),
	/// The input could not be decoded because it exceeds the max allowed
	/// length.
	// See `STR_MAX_LENGTH` for the max length.
	ExceedsMaxLength,
	/// A non ascii char was used as input
	NonAsciiChar,
	/// Invalid UTF-8 byte vector when converting to String
	InvalidUtf8(FromUtf8Error),
}

impl From<ParseIntError> for HexError {
	fn from(e: ParseIntError) -> Self {
		HexError::ParseInt(e)
	}
}

impl From<FromUtf8Error> for HexError {
	fn from(e: FromUtf8Error) -> Self {
		HexError::InvalidUtf8(e)
	}
}

fn verify_ascii(byte: &u8) -> Result<(), HexError> {
	if byte >= &128 {
		return Err(HexError::NonAsciiChar);
	}
	Ok(())
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
pub fn decode(raw_s: &str) -> Result<Vec<u8>, HexError> {
	let sanitized_s = match raw_s.len() {
		0 => return Ok(Vec::new()),
		1 => return Err(HexError::LengthOne),
		_ => {
			if &raw_s.as_bytes()[0..2] == b"0x" {
				&raw_s[2..]
			} else {
				raw_s
			}
		}
	};

	let sanitized_s_byte_len = sanitized_s.len();
	let is_even_len = sanitized_s_byte_len % 2 == 0;
	let is_lt_max_len = sanitized_s_byte_len < STR_MAX_LENGTH;
	match (is_even_len, is_lt_max_len) {
		(true, true) => {
			let sanitized_s_bytes = sanitized_s.as_bytes();
			(0..sanitized_s_byte_len)
				.step_by(2)
				.map(|i| {
					// check that both bytes represent ascii chars
					verify_ascii(&sanitized_s_bytes[i])?;
					verify_ascii(&sanitized_s_bytes[i + 1])?;

					let s = std::str::from_utf8(&sanitized_s_bytes[i..i+2])
						.expect("We ensure that input slice represents ASCII above. qed.");
					u8::from_str_radix(s, 16).map_err(Into::into)
				})
				.collect()
		}
		(true, false) | (false, false) => Err(HexError::ExceedsMaxLength),
		(false, true) => Err(HexError::OddLength),
	}
}

#[must_use]
pub fn decode_from_vec(vec: Vec<u8>) -> Result<Vec<u8>, HexError> {
	let hex_string = String::from_utf8(vec).map_err(HexError::from)?;
	let hex_string = hex_string.trim();
	decode(&hex_string)
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

/// Encode a byte slice to a hex-encoded byte slice.
#[must_use]
pub fn encode_to_vec(bytes: &[u8]) -> Vec<u8> {
	encode(bytes).into_bytes()
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn decode_works_with_len_zero() {
		let encoded = "";
		let res = decode(encoded);
		assert_eq!(res, Ok(Vec::new()));
	}

	#[test]
	fn decode_correctly_errors_with_len_one() {
		let encoded = "a";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::LengthOne));

		let encoded = " ";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::LengthOne));
	}

	#[test]
	fn decode_correctly_errors_with_non_ascii() {
		// minimal example
		let encoded = "0fÓ";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::NonAsciiChar));

		let encoded = "0x0fÓ";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::NonAsciiChar));

		// when its the first char
		let encoded = "Óff";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::NonAsciiChar));

		// example taken from fuzzing
		let encoded = "C6ff584301800c5f60000000000000000000000000Óf8$6800;033333333333333333333333344444444333";
		let res = decode(encoded);
		assert_eq!(res, Err(HexError::NonAsciiChar));
	}

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

		let decoded = vec![31, 52, 228, 109, 140, 170, 124, 94];
		let encoded = "1f34e46d8caa7c5e";
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);
	}

	#[test]
	fn encode_and_decode_with_all_hex_chars() {
		let decoded: Vec<_> = (0..=255u8).collect();
		let encoded = HEX_BYTES;
		assert_eq!(encode(&decoded), encoded);
		assert_eq!(decode(encoded).unwrap(), decoded);
	}

	#[test]
	fn encode_and_decode_handles_0x_prefix_and_mixed_casing() {
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
	}

	#[test]
	fn decode_rejects_invalid_hex() {
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

	#[test]
	fn encode_to_vec_and_decode_from_vec_with_len_zero() {
		let decoded = vec![];
		let encoded = vec![];
		assert_eq!(encode_to_vec(&decoded), encoded);
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);
	}

	#[test]
	fn decode_from_vec_correctly_errors_with_len_one() {
		// "a" hexadecimal string
		let encoded = vec![0x61];
		let res = decode_from_vec(encoded);
		assert_eq!(res, Err(HexError::LengthOne));
	}

	#[test]
	fn decode_from_vec_trims_string() {
		// " " hexadecimal string
		let encoded = vec![0x20];
		let decoded = vec![];
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);

		// "a " hexadecimal string
		let encoded = vec![0x61, 0x20];
		let res = decode_from_vec(encoded);
		assert_eq!(res, Err(HexError::LengthOne));

		// "aa " hexadecimal string
		let encoded = vec![0x61, 0x61, 0x20];
		let decoded = vec![170];
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);
	}

	#[test]
	fn encode_to_vec_and_decode_from_vec_work() {
		// "00000000" hexadecimal string
		let decoded = vec![0, 0, 0, 0];
		let encoded = vec![48, 48, 48, 48, 48, 48, 48, 48];
		assert_eq!(encode_to_vec(&decoded), encoded);
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);

		// "ff00ff" hexadecimal string
		let decoded = vec![0xff, 0x00, 0xff];
		let encoded = vec![102, 102, 48, 48, 102, 102];
		assert_eq!(encode_to_vec(&decoded), encoded);
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);

		// "1f34e46d8caa7c5e" hexadecimal string
		let decoded = vec![31, 52, 228, 109, 140, 170, 124, 94];
		let encoded = vec![
			49, 102, 51, 52, 101, 52, 54, 100, 56, 99, 97, 97, 55, 99, 53, 101,
		];
		assert_eq!(encode_to_vec(&decoded), encoded);
		assert_eq!(decode_from_vec(encoded).unwrap(), decoded);
	}

	#[test]
	fn decode_from_vec_rejects_invalid_hex() {
		// Rejects invalid UTF-8 byte sequence
		let invalid = vec![240, 159, 144];
		let is_err = matches!(
			decode_from_vec(invalid),
			Err(HexError::InvalidUtf8(FromUtf8Error { .. }))
		);
		assert!(is_err);
	}
}
