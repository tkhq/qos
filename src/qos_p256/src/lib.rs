//! Abstractions for authentication and encryption with NIST-P256.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: usize = 65;

pub mod encrypt;
pub mod sign;

/// Errors for qos P256.
#[derive(Debug, PartialEq)]
pub enum P256Error {
	/// The encryption envelope should not be serialized. This is likely a bug
	/// with the code.
	FailedToSerializeEnvelope,
	/// The encryption envelope could not be deserialized.
	FailedToDeserializeEnvelope,
	/// An error while decrypting the ciphertext with the `AesGcm256` cipher.
	AesGcm256DecryptError,
	/// An error while encrypting the plaintext with the `AesGcm256` cipher.
	AesGcm256EncryptError,
	/// Failed to create the `AesGcm256` cipher.
	FailedToCreateAes256GcmCipher,
	/// The public key could not be deserialized.
	FailedToDeserializePublicKey,
	/// Public Key could not be coerced into the intended length.
	FailedToCoercePublicKeyToIntendedLength,
	/// Nonce could not be coerced into the intended length.
	FailedToCoerceNonceToIntendedLength,
	/// Signature could not be de-serialized as DER encoded.
	FailedToDeserializeSignatureAsDer,
	/// The signature could not be verified against the given message and
	/// public key.
	FailedSignatureVerification,
	/// Could not deserialize a public key as `SEC1` encoded.
	FailedToDeserializePublicKeyFromSec1,
	/// Could not deserialize a private key as `SEC1` encoded.
	FailedToDeserializePrivateKeyFromSec1,
	/// The raw bytes could not be interpreted as a P256 secret.
	FailedToReadSecret,
	/// The raw bytes could not be interpreted as SEC1 encoded point uncompressed.
	FailedToReadPublicKey,
	/// Failed to convert public key to der.
	FailedToConvertPublicKeyToDer,
	/// Failed to convert private key to der.
	FailedToConvertPrivateKeyToDer,
	/// Failed to create a public key in constant time (or possibly some other
	/// failures while creating public key).
	CouldNotCreatePublicKeyInConstantTime,
	/// The DER encoded public key is too long to be valid.
	EncodedPublicKeyTooLong,
	/// The DER encoded public key is too short to be valid.
	EncodedPublicKeyTooShort,
	/// The DER encoded private key is too long to be valid.
	EncodedPrivateKeyTooLong,
	/// The DER encoded private key is too short to be valid.
	EncodedPrivateKeyTooShort,
}

/// P256 private key pair for signing and encryption. Internally this uses a
/// separate secret for signing and encryption.
pub struct P256Pair {
	encrypt_private: P256EncryptPair,
	sign_private: P256SignPair,
}

impl P256Pair {
	/// Generate a new private key using the OS randomness source.
	#[must_use]
	pub fn generate() -> Self {
		Self {
			encrypt_private: P256EncryptPair::generate(),
			sign_private: P256SignPair::generate(),
		}
	}

	/// Decrypt a message encoded to this pair's public key.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		self.encrypt_private.decrypt(serialized_envelope)
	}

	/// Sign the message and return the ASN.1 DER. Signs the SHA512 digest of
	/// the message.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		self.sign_private.sign(message)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> P256Public {
		P256Public {
			encrypt_public: self.encrypt_private.public_key(),
			sign_public: self.sign_private.public_key(),
		}
	}
}

/// P256 public key for signing and encryption. Internally this uses a
/// separate public keys for signing and encryption.
pub struct P256Public {
	encrypt_public: P256EncryptPublic,
	sign_public: P256SignPublic,
}

impl P256Public {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		self.encrypt_public.encrypt(message)
	}

	/// Verify a `signature` and `message` against this private key. Verifies
	/// the SHA512 digest of the message.
	///
	/// Returns Ok if the signature is good.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), P256Error> {
		self.sign_public.verify(message, signature)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn signatures_are_deterministic() {
		let message = b"a message to authenticate";

		let pair = P256Pair::generate();
		(0..100)
			.map(|_| pair.sign(message).unwrap().to_vec())
			.collect::<Vec<_>>()
			.windows(2)
			.for_each(|slice| assert_eq!(slice[0], slice[1]));
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = P256Pair::generate();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = P256Pair::generate();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = P256Pair::generate().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			P256Error::FailedSignatureVerification
		);
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = P256Pair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = P256Pair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let bob_pair = P256Pair::generate();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			P256Error::AesGcm256DecryptError
		);
	}
}
