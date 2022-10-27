//! Abstractions for encryption.

use aes_gcm::{
	aead::{Aead, KeyInit, Payload},
	Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use p256::{
	ecdh::EphemeralSecret,
	elliptic_curve::{sec1::ToEncodedPoint, zeroize::Zeroize},
	PublicKey,
};
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
	ephemeral_sender_public: [u8; PUB_KEY_LEN_UNCOMPRESSED],
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
		let Envelope {
			nonce,
			ephemeral_sender_public: ephemeral_sender_public_bytes,
			encrypted_message,
		} = Envelope::try_from_slice(serialized_envelope)
			.map_err(|_| P256Error::FailedToDeserializeEnvelope)?;

		let nonce = Nonce::from_slice(&nonce);
		let ephemeral_sender_public =
			PublicKey::from_sec1_bytes(&ephemeral_sender_public_bytes)
				.map_err(|_| P256Error::FailedToDeserializePublicKey)?;

		let sender_public_typed = SenderPublic(&ephemeral_sender_public_bytes);
		let receiver_encoded_point =
			self.private.public_key().to_encoded_point(false);
		let receiver_public_typed =
			ReceiverPublic(receiver_encoded_point.as_ref());

		let cipher = create_cipher(
			&self.private,
			&ephemeral_sender_public,
			&sender_public_typed,
			&receiver_public_typed,
		)?;

		let aad = create_additional_associated_data(
			&sender_public_typed,
			&receiver_public_typed,
			nonce.as_ref(),
		);
		let payload = Payload { aad: &aad, msg: &encrypted_message };

		cipher
			.decrypt(nonce, payload)
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
		self.private.zeroize();
	}
}

/// P256 Public key.
pub struct P256EncryptPublic {
	public: PublicKey,
}

impl P256EncryptPublic {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		let ephemeral_sender_private = EphemeralSecret::random(&mut OsRng);
		let ephemeral_sender_public: [u8; PUB_KEY_LEN_UNCOMPRESSED] =
			ephemeral_sender_private
				.public_key()
				.to_encoded_point(false)
				.as_ref()
				.try_into()
				.map_err(|_| {
					P256Error::FailedToCoercePublicKeyToIntendedLength
				})?;

		let sender_public_typed = SenderPublic(&ephemeral_sender_public);
		let receiver_encoded_point = self.public.to_encoded_point(false);
		let receiver_public_typed =
			ReceiverPublic(receiver_encoded_point.as_ref());

		let cipher = create_cipher(
			&ephemeral_sender_private,
			&self.public,
			&sender_public_typed,
			&receiver_public_typed,
		)?;

		let nonce = {
			let random_bytes =
				rand::thread_rng().gen::<[u8; BITS_96_AS_BYTES]>();
			*Nonce::from_slice(&random_bytes)
		};

		let aad = create_additional_associated_data(
			&sender_public_typed,
			&receiver_public_typed,
			nonce.as_ref(),
		);
		let payload = Payload { aad: &aad, msg: message };

		let encrypted_message = cipher
			.encrypt(&nonce, payload)
			.map_err(|_| P256Error::AesGcm256EncryptError)?;

		let nonce = nonce
			.try_into()
			.map_err(|_| P256Error::FailedToCoerceNonceToIntendedLength)?;

		let envelope =
			Envelope { nonce, ephemeral_sender_public, encrypted_message };

		envelope.try_to_vec().map_err(|_| P256Error::FailedToSerializeEnvelope)
	}
}

// Types for helper function parameters to help prevent fat finger mistakes.
struct SenderPublic<'a>(&'a [u8]);
struct ReceiverPublic<'a>(&'a [u8]);

// Helper function to create the `Aes256Gcm` cypher.
fn create_cipher(
	private: &EphemeralSecret,
	public: &PublicKey,
	ephemeral_sender_public: &SenderPublic,
	receiver_public: &ReceiverPublic,
) -> Result<Aes256Gcm, P256Error> {
	let shared_secret = private.diffie_hellman(public);
	// To help with entropy and add domain context, we do
	// `sender_public||receiver_public||shared_secret` as the pre-image for the
	// shared key.
	let pre_image: Vec<u8> = ephemeral_sender_public
		.0
		.iter()
		.chain(receiver_public.0)
		.chain(shared_secret.raw_secret_bytes())
		.copied()
		.collect();

	let shared_key = sha2::Sha512::digest(&pre_image);
	Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN])
		.map_err(|_| P256Error::FailedToCreateAes256GcmCipher)
}

// Helper function to create the additional associated data (AAD). The data is
// of the form `sender_public||receiver_public||nonce`.
fn create_additional_associated_data(
	ephemeral_sender_public: &SenderPublic,
	receiver_public: &ReceiverPublic,
	nonce: &[u8],
) -> Vec<u8> {
	ephemeral_sender_public
		.0
		.iter()
		.chain(receiver_public.0)
		.chain(nonce)
		.copied()
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();

		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let bob_pair = P256EncryptPair::generate();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			P256Error::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_encrypted_message_fails() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let mut envelope =
			Envelope::try_from_slice(&serialized_envelope).unwrap();

		envelope.encrypted_message.push(0);
		let tampered_envelope = envelope.try_to_vec().unwrap();

		assert_eq!(
			alice_pair.decrypt(&tampered_envelope).unwrap_err(),
			P256Error::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_nonce_errors() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let mut envelope =
			Envelope::try_from_slice(&serialized_envelope).unwrap();

		// Alter the first byte of the nonce.
		if envelope.nonce[0] == 0 {
			envelope.nonce[0] = 1;
		} else {
			envelope.nonce[0] = 0;
		};
		let tampered_envelope = envelope.try_to_vec().unwrap();

		assert_eq!(
			alice_pair.decrypt(&tampered_envelope).unwrap_err(),
			P256Error::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_ephemeral_sender_key_errors() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let mut envelope =
			Envelope::try_from_slice(&serialized_envelope).unwrap();

		// Alter the first byte of the sender's public key.
		if envelope.ephemeral_sender_public[0] == 0 {
			envelope.ephemeral_sender_public[0] = 1;
		} else {
			envelope.ephemeral_sender_public[0] = 0;
		};
		let tampered_envelope = envelope.try_to_vec().unwrap();

		assert_eq!(
			alice_pair.decrypt(&tampered_envelope).unwrap_err(),
			P256Error::FailedToDeserializePublicKey
		);
	}

	#[test]
	fn tampered_envelope_errors() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let mut serialized_envelope = alice_public.encrypt(plaintext).unwrap();
		// Given borsh encoding, this should be a byte in the nonce. We insert a
		// byte and shift everthing after, making the nonce too long.
		serialized_envelope.insert(BITS_96_AS_BYTES, 0xff);

		assert_eq!(
			alice_pair.decrypt(&serialized_envelope).unwrap_err(),
			P256Error::FailedToDeserializeEnvelope
		);
	}
}
