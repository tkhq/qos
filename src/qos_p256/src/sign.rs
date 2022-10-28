//! Abstractions for sign and signature verification

use der::zeroize::Zeroizing;
use p256::{
	ecdsa::{
		signature::{Signer, Verifier},
		Signature, SigningKey, VerifyingKey,
	},
	elliptic_curve::sec1::FromEncodedPoint,
	pkcs8::{DecodePublicKey, EncodePublicKey},
	PublicKey, SecretKey,
};
use rand_core::OsRng;
use sha2::Digest;

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

	/// Create private key from `SEC1` der.
	pub fn from_der(bytes: &[u8]) -> Result<Self, P256Error> {
		let secret_key = SecretKey::from_sec1_der(bytes)
			.map_err(|_| P256Error::FailedToDeserializePrivateKeyFromSec1)?;
		Ok(Self { private: SigningKey::from(&secret_key) })
	}

	/// Convert to `SEC1` der.
	pub fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, P256Error> {
		let scalar = self.private.as_nonzero_scalar();
		let secret_key = SecretKey::from(scalar);
		secret_key
			.to_sec1_der()
			.map_err(|_| P256Error::FailedToConvertPrivateKeyToDer)
	}

	pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, P256Error> {
		let bytes = self.private.to_bytes().to_vec();

		Ok(Zeroizing::new(
			bytes
		))
	}

	// pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {

	// }
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
		let signature = Signature::from_der(signature)
			.map_err(|_| P256Error::FailedToDeserializeSignatureAsDer)?;

		self.public
			.verify(&digest, &signature)
			.map_err(|_| P256Error::FailedSignatureVerification)
	}

	/// Initialize from a sec1 encoded public key.
	pub fn from_der(bytes: &[u8]) -> Result<Self, P256Error> {
		let public_key = PublicKey::from_public_key_der(bytes)
			.map_err(|_| P256Error::FailedToDeserializePublicKeyFromSec1)?;
		// let encoded_point = public_key.to_encoded_point(false);
		Ok(Self { public: VerifyingKey::from(&public_key) })
	}

	/// Serialize as `SEC1` encoded point.
	pub fn to_der(&self) -> Result<der::Document, P256Error> {
		let sec1_encoded_point = self.public.to_encoded_point(false);
		let maybe_public = PublicKey::from_encoded_point(&sec1_encoded_point);
		if maybe_public.is_some().unwrap_u8() == 1 {
			maybe_public
				.unwrap()
				.to_public_key_der()
				.map_err(|_| P256Error::FailedToConvertPublicKeyToDer)
		} else {
			Err(P256Error::CouldNotCreatePublicKeyInConstantTime)
		}
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
	fn public_key_round_trip_der_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let der_public = pair.public_key().to_der().unwrap();
		let signature = pair.sign(message).unwrap();

		let public = P256SignPublic::from_der(der_public.as_bytes()).unwrap();

		assert!(public.verify(message, &signature).is_ok());
	}

	#[test]
	fn private_key_roundtrip_serialization_works() {
		let pair = P256SignPair::generate();
		let raw_secret1 = pair.to_der().unwrap();

		let pair2 = P256SignPair::from_der(&raw_secret1).unwrap();
		let raw_secret2 = pair2.to_der().unwrap();

		assert_eq!(raw_secret1, raw_secret2);
	}
}
