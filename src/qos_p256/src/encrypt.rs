//! Abstractions for encryption.

use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use p256::{
	ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey,
};
use p256::elliptic_curve::zeroize::Zeroize;
use rand::Rng;
use rand_core::OsRng;
use sha2::Digest;
use crate::P256Error;

const AES256_KEY_LEN: usize = 32;
const BITS_96_AS_BYTES: usize = 12;
const PUB_KEY_LEN_UNCOMPRESSED: usize = 65;

/// Envelope for serializing an encrypted message with it's context.
#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
struct Envelope {
	/// Nonce used as an input to the cipher.
	nonce: [u8; BITS_96_AS_BYTES],
	/// Public key as sec1 encoded point with no compression
	ephemeral_public: [u8; PUB_KEY_LEN_UNCOMPRESSED],
	/// The data encrypted with an AES 256 GCM cipher.
	encrypted_message: Vec<u8>,
}

/// P256 key pair
pub struct P256EncryptPair {
	private: EphemeralSecret,
}

impl P256EncryptPair {
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
	pub fn public_key(&self) -> P256EncryptPublic {
		P256EncryptPublic { public: self.private.public_key() }
	}
}

impl Drop for P256EncryptPair {
	fn drop(&mut self) {
		self.private.zeroize()
	}
}

/// P256 Public key.
pub struct P256EncryptPublic {
	public: PublicKey,
}

impl P256EncryptPublic {
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

		let ephemeral_public = ephemeral_public
				.to_encoded_point(false)
				.as_ref()
				.try_into()
				.map_err(|_| P256Error::FailedToCoercePublicKeyToIntendedLength)?;

		let nonce =  nonce.try_into()
			.map_err(|_| P256Error::FailedToCoerceNonceToIntendedLength)?;

		let envelope = Envelope {
			encrypted_message,
			nonce,
			ephemeral_public,
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
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();

		assert_eq!(decrypted, plaintext);
	}

	// What other edge cases should we test for?
}
