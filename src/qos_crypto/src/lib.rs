//! Cryptographic primitves for use with `QuorumOS`.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use sha2::Digest;

pub mod shamir;

/// Create a SHA256 hash digest of `buf`.
#[must_use]
pub fn sha_256(buf: &[u8]) -> [u8; 32] {
	let mut hasher = sha2::Sha256::new();
	hasher.update(buf);
	hasher.finalize().try_into().expect("sha256 digest is 32 bytes")
}

/// Create a SHA384 hash digest of `buf`.
#[must_use]
pub fn sha_384(buf: &[u8]) -> [u8; 48] {
	let mut hasher = sha2::Sha384::new();
	hasher.update(buf);
	hasher.finalize().try_into().expect("sha384 digest is 48 bytes")
}

/// Create a SHA512 hash digest of `buf`.
#[must_use]
pub fn sha_512(buf: &[u8]) -> [u8; 64] {
	let mut hasher = sha2::Sha512::new();
	hasher.update(buf);
	hasher.finalize().try_into().expect("sha512 digest is 64 bytes")
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn sha_384_can_make_pcr3() {
		let role_arn = "arn:aws:iam::123456789012:role/Webserver";

		let mut buf = [0u8; 48].to_vec();
		buf.extend_from_slice(role_arn.as_bytes());

		let digest = sha_384(&buf);
		let pcr3 = qos_hex::encode(&digest);

		assert_eq!(
			pcr3,
			"78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6"
		);
	}

	#[test]
	fn sha_512_works() {
		let msg = b"test-msg";

		let digest = sha_512(msg);

		assert_eq!(
			qos_hex::encode(&digest),
			"ed1cd50fc10f1129894f38f0dfa2d00642cfc7302cbf11ec22303d65697e18eb7594a03e2b8b9d3aac58b4b8c9af7d45335ecd34dc779ab1d3516c3e12bd171e"
		);
	}
}
