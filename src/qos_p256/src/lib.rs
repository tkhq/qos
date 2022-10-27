//! Abstractions for authentication and encryption with NIST-P256.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use p256::{
	ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey,
};
use rand::Rng;
use rand_core::OsRng;
use sha2::Digest;

const AES256_KEY_LEN: usize = 32;
const BITS_96_AS_BYTES: usize = 12;

/// Errors for qos P256.
#[derive(Debug)]
pub enum P256Error {
	/// The encryption envelope should not be serialized. This is likely a bug
	/// with the code.
	FailedToSerializeEnvelope,
	/// The encryption envelope could not be deserialized.
	InvalidEnvelope,
	/// An error while decrypting the ciphertext with the `AesGcm256` cipher.
	AesGcm256DecryptError,
	/// An error while encrypting the plaintext with the `AesGcm256` cipher.
	AesGcm256EncryptError,
	/// Failed to create the `AesGcm256` cipher.
	FailedToCreateAes256GcmCipher,
	/// The public key could not be deserialized.
	FailedToDeserializePublicKey,
}

/// Envelope for serializing an encrypted message with it's context.
#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
struct Envelope {
	/// Nonce used as an input to the cipher.
	nonce: Vec<u8>,
	/// Public key as sec1 encoded point with no compression
	ephemeral_public: Vec<u8>,
	/// The data encrypted with an AES 256 GCM cipher.
	encrypted_message: Vec<u8>,
}

/// P256 key pair
pub struct P256Pair {
	private: EphemeralSecret,
}

impl P256Pair {
	/// Generate a new private key using the OS randomness source.
	#[must_use]
	pub fn generate() -> Self {
		Self { private: EphemeralSecret::random(&mut OsRng) }
	}

	/// Decrypt a message encoded to this pair's public key.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		let Envelope { nonce, ephemeral_public, encrypted_message } =
			Envelope::try_from_slice(serialized_envelope)
				.map_err(|_| P256Error::InvalidEnvelope)?;

		let nonce = Nonce::from_slice(&nonce);
		let ephemeral_public = PublicKey::from_sec1_bytes(&ephemeral_public)
			.map_err(|_| P256Error::FailedToDeserializePublicKey)?;

		let cipher = create_cipher(&self.private, &ephemeral_public)?;

		cipher
			.decrypt(nonce, &*encrypted_message)
			.map_err(|_| P256Error::AesGcm256DecryptError)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> P256Public {
		P256Public { public: self.private.public_key() }
	}
}

/// P256 Public key.
pub struct P256Public {
	public: PublicKey,
}

impl P256Public {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		let ephemeral_private = EphemeralSecret::random(&mut OsRng);
		let ephemeral_public = ephemeral_private.public_key();

		let cipher = create_cipher(&ephemeral_private, &self.public)?;

		let nonce = {
			let random_bytes =
				rand::thread_rng().gen::<[u8; BITS_96_AS_BYTES]>();
			*Nonce::from_slice(&random_bytes)
		};

		// TODO: use nonce||ephemeral_public as authenticated data .. although
		// doesn't seem strictly necessary
		let encrypted_message = cipher
			.encrypt(&nonce, message)
			.map_err(|_| P256Error::AesGcm256EncryptError)?;

		let envelope = Envelope {
			encrypted_message,
			nonce: nonce.to_vec(),
			ephemeral_public: ephemeral_public
				// TODO: Should we do compression? Is there a better way to
				// serialize the public key.
				.to_encoded_point(false)
				.as_ref()
				.to_vec(),
		};

		envelope.try_to_vec().map_err(|_| P256Error::FailedToSerializeEnvelope)
	}

	// TODO: from der/sec1 etc
}

// Helper function to create the `Aes256Gcm` cypher.
fn create_cipher(
	private: &EphemeralSecret,
	public: &PublicKey,
) -> Result<Aes256Gcm, P256Error> {
	let shared_secret = private.diffie_hellman(public);
	let shared_key = sha2::Sha512::digest(shared_secret.raw_secret_bytes());
	Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN])
		.map_err(|_| P256Error::FailedToCreateAes256GcmCipher)
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn basic_encrypt_decrypt() {
		let alice_pair = P256Pair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();

		assert_eq!(decrypted, plaintext);
	}

	// What other edge cases should we test for?
}
