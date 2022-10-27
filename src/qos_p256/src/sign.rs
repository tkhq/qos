//! Abstractions for signing and signature verification

use p256::ecdsa::{
	signature::{Signer, Verifier},
	Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;
use sha2::Digest;

use crate::P256Error;

/// Signing private key pair.
pub struct P256SignPair {
	private: SigningKey,
}

impl P256SignPair {
	/// Generate a new private key
	#[must_use]
	pub fn generate() -> Self {
		Self { private: SigningKey::random(&mut OsRng) }
	}

	/// Sign the message and return the ASN.1 DER
	pub fn sign(&self, message: &[u8]) -> Result<Box<[u8]>, P256Error> {
		let digest = sha2::Sha512::digest(message);
		let signature: Signature = self.private.sign(&digest);

		Ok(signature.to_der().to_bytes())
	}

	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> P256SignPublic {
		P256SignPublic { public: VerifyingKey::from(&self.private) }
	}
}

/// Signing public key for verifying signatures.
pub struct P256SignPublic {
	public: VerifyingKey,
}

impl P256SignPublic {
	/// Verify a `signature` and `message` against this private key. Returns Ok
	/// if the signature is good.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), P256Error> {
		let digest = sha2::Sha512::digest(message);
		let signature = Signature::from_der(signature)
			.map_err(|_| P256Error::FailedToDeserializeSignatureAsDer)?;

		self.public
			.verify(&digest, &signature)
			.map_err(|_| P256Error::FailedSignatureVerification)
	}

	/// Initialize from a sec1 encoded public key.
	pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			public: VerifyingKey::from_sec1_bytes(bytes)
				.map_err(|_| P256Error::FailedToDeserializePublicKeyFromSec1)?,
		})
	}

	/// Serialize as `SEC1` encoded point.
	#[must_use]
	pub fn to_sec1_bytes(&self) -> Box<[u8]> {
		self.public.to_encoded_point(false).to_bytes()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signing_and_verification_works() {
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
	fn public_key_round_trip_serialization_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let serialized_public = pair.public_key().to_sec1_bytes();
		let signature = pair.sign(message).unwrap();

		let public =
			P256SignPublic::from_sec1_bytes(&serialized_public).unwrap();

		assert!(public.verify(message, &signature).is_ok());
	}
}
