//! Abstractions for authentication and encryption with NIST-P256.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use der::zeroize::Zeroizing;

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: usize = 65;
const PUB_KEY_DER_LEN: usize = 91;
const PRIVATE_KEY_DER_LEN: usize = 109;

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
	pub fn sign(&self, message: &[u8]) -> Result<Box<[u8]>, P256Error> {
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

	/// Serialize private keys to `SEC1` DER, creating a single value of `encrypt_private_der||sign_private_der`
	pub fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, P256Error> {
		let mut encrypt_der = self.encrypt_private.to_der()?;
		let sign_der = self.sign_private.to_der()?;

		encrypt_der.extend_from_slice(&*sign_der);

		Ok(encrypt_der)
	}

	/// Deserialize private keys from `SEC1` DER. Assumes the given bytes are encoded as `encrypt_private_der||sign_private_der`.
	pub fn from_der(bytes: &[u8]) -> Result<Self, P256Error> {
		if bytes.len() > PRIVATE_KEY_DER_LEN * 2 {
			return Err(P256Error::EncodedPrivateKeyTooLong);
		}
		if bytes.len() < PRIVATE_KEY_DER_LEN * 2 {
			return Err(P256Error::EncodedPrivateKeyTooShort);
		}

		// encrypt private is (0, PRIVATE_KEY_DER_LEN].
		// sign private is (PRIVATE_KEY_DER_LEN, PRIVATE_KEY_DER_LEN*2].
		let (encrypt_der, sign_der) = bytes.split_at(PRIVATE_KEY_DER_LEN);

		Ok(Self {
			encrypt_private: P256EncryptPair::from_der(encrypt_der)?,
			sign_private: P256SignPair::from_der(sign_der)?,
		})
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

	/// Deserialize the public key from a single DER encoded slice. Assumes the
	/// keys are serialized as `encrypt_public_der||sign_public_der`.
	pub fn from_der(bytes: &[u8]) -> Result<Self, P256Error> {
		// encrypt public is 0..PUB_KEY_DER_LEN.
		// sign public is PUB_KEY_DER_LEN..(PUB_KEY_DER_LEN*2).
		if bytes.len() > PUB_KEY_DER_LEN * 2 {
			return Err(P256Error::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUB_KEY_DER_LEN * 2 {
			return Err(P256Error::EncodedPublicKeyTooShort);
		}

		// encrypt public is (0, PUB_KEY_DER_LEN].
		// sign public is (PUB_KEY_DER_LEN, PUB_KEY_DER_LEN*2].
		let (encrypt_der, sign_der) = bytes.split_at(PUB_KEY_DER_LEN);

		Ok(Self {
			encrypt_public: P256EncryptPublic::from_der(encrypt_der)?,
			sign_public: P256SignPublic::from_der(sign_der)?,
		})
	}

	/// Serialize the public keys to a single DER encoded vec. Serialized as
	/// `encrypt_public_der||sign_public_der`.
	pub fn to_der(&self) -> Result<Vec<u8>, P256Error> {
		let encrypt_doc = self.encrypt_public.to_der()?;
		let sign_doc = self.sign_public.to_der()?;

		let der = encrypt_doc
			.as_bytes()
			.iter()
			.chain(sign_doc.as_bytes())
			.copied()
			.collect();

		Ok(der)
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

	#[test]
	fn public_key_roundtrip_serialization_works() {
		let message = b"a message to authenticate";
		let alice_pair = P256Pair::generate();
		let signature = alice_pair.sign(message).unwrap();

		let alice_public = alice_pair.public_key();
		let alice_public_der = alice_public.to_der().unwrap();

		assert_eq!(alice_public_der.len(), PUB_KEY_DER_LEN * 2);

		let alice_public2 = P256Public::from_der(&alice_public_der).unwrap();
		assert!(alice_public2.verify(message, &signature).is_ok());

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();
		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn private_key_roundtrip_serialization_works() {
		let alice_pair = P256Pair::generate();
		let alice_public = alice_pair.public_key();

		let alice_pair_der = alice_pair.to_der().unwrap();
		assert_eq!(alice_pair_der.len(), PRIVATE_KEY_DER_LEN * 2);
		let alice_pair2 = P256Pair::from_der(&alice_pair_der).unwrap();

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(alice_public.verify(message, &signature).is_ok());

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

	}
}
