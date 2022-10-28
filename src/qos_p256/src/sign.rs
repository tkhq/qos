//! Abstractions for sign and signature verification

use p256::{
	ecdsa::{
		signature::{Signer, Verifier},
		Signature, SigningKey, VerifyingKey,
	},
};
use rand_core::OsRng;
use sha2::Digest;
use p256::ecdsa::signature::Signature as _;

use crate::P256Error;

/// Sign private key pair.
pub struct P256SignPair {
	private: SigningKey,
}

impl P256SignPair {
	/// Generate a new private key
	#[must_use]
	pub fn generate() -> Self {
		Self { private: SigningKey::random(&mut OsRng) }
	}

	/// Sign the message and return the ASN.1 DER. Signs the SHA512 digest of
	/// the message.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		let digest = sha2::Sha512::digest(message);
		let signature: Signature = self.private.sign(&digest);

		Ok(signature.to_vec())
	}

	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> P256SignPublic {
		P256SignPublic { public: VerifyingKey::from(&self.private) }
	}

	/// Deserialize key from raw scalar byte slice.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			private: SigningKey::from_bytes(bytes)
				.map_err(|_| P256Error::FailedToReadSecret)?,
		})
	}

	/// Serialize key to raw scalar byte slice.
	pub fn to_bytes(&self) -> Vec<u8> {
		let bytes = self.private.to_bytes().to_vec();

		bytes
	}
}

/// Sign public key for verifying signatures.
pub struct P256SignPublic {
	public: VerifyingKey,
}

impl P256SignPublic {
	/// Verify a `signature` and `message` against this private key. Verifies
	/// the SHA512 digest of the message.
	///
	/// Returns Ok if the signature is good.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), P256Error> {
		let digest = sha2::Sha512::digest(message);
		let signature = Signature::from_bytes(signature)
			.map_err(|_| P256Error::FailedToDeserializeSignatureAsDer)?;

		self.public
			.verify(&digest, &signature)
			.map_err(|_| P256Error::FailedSignatureVerification)
	}

	/// Serialize to SEC1 encoded point, not compressed.
	pub fn to_bytes(&self) -> Box<[u8]> {
		let sec1_encoded_point = self.public.to_encoded_point(false);
		sec1_encoded_point.to_bytes()
	}

	/// Deserialize from a SEC1 encoded point, not compressed.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			public: VerifyingKey::from_sec1_bytes(bytes).map_err(|_| P256Error::FailedToReadPublicKey)?
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = P256SignPair::generate();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = P256SignPair::generate().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			P256Error::FailedSignatureVerification
		);
	}

	#[test]
	fn public_key_round_trip_bytes_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let bytes_public = pair.public_key().to_bytes();
		let signature = pair.sign(message).unwrap();

		let public = P256SignPublic::from_bytes(&bytes_public).unwrap();

		assert!(public.verify(message, &signature).is_ok());
	}

	#[test]
	fn private_key_roundtrip_bytes_works() {
		let pair = P256SignPair::generate();
		let raw_secret1 = pair.to_bytes();

		let pair2 = P256SignPair::from_bytes(&raw_secret1).unwrap();
		let raw_secret2 = pair2.to_bytes();

		assert_eq!(raw_secret1, raw_secret2);
	}
}
