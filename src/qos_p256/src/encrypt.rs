//! Abstractions for encryption.

use aes_gcm::{
	aead::{Aead, KeyInit, Payload},
	Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, Mac};
use p256::{
	ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey,
	SecretKey,
};
use rand_core::OsRng;
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::{bytes_os_rng, P256Error, PUB_KEY_LEN_UNCOMPRESSED};

const AES256_KEY_LEN: usize = 32;
const BITS_96_AS_BYTES: u8 = 12;
const AES_GCM_256_HMAC_SHA512_TAG: &[u8] = b"qos_aes_gcm_256_hmac_sha512";
const QOS_ENCRYPTION_HMAC_MESSAGE: &[u8] = b"qos_encryption_hmac_message";

type HmacSha512 = Hmac<Sha512>;

/// Envelope for serializing an encrypted message with it's context.
#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Envelope {
	/// Nonce used as an input to the cipher.
	nonce: [u8; BITS_96_AS_BYTES as usize],
	/// Public key as sec1 encoded point with no compression
	pub ephemeral_sender_public: [u8; PUB_KEY_LEN_UNCOMPRESSED as usize],
	/// The data encrypted with an AES 256 GCM cipher.
	encrypted_message: Vec<u8>,
}

/// P256 key pair.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct P256EncryptPair {
	private: SecretKey,
}

impl P256EncryptPair {
	/// Generate a new private key using the OS randomness source.
	#[must_use]
	pub fn generate() -> Self {
		Self { private: SecretKey::random(&mut OsRng) }
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
			&PrivPubOrSharedSecret::PrivPub {
				private: &self.private,
				public: &ephemeral_sender_public,
			},
			&sender_public_typed,
			&receiver_public_typed,
		)?;

		let aad = create_additional_associated_data(
			&sender_public_typed,
			&receiver_public_typed,
		)?;
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

	/// Deserialize key from raw scalar byte slice.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			private: SecretKey::from_be_bytes(bytes)
				.map_err(|_| P256Error::FailedToReadSecret)?,
		})
	}

	/// Serialize key to raw scalar byte slice.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		self.private.to_be_bytes().to_vec()
	}
}

/// P256 Public key.
#[derive(Clone, PartialEq, Eq)]
pub struct P256EncryptPublic {
	public: PublicKey,
}

impl P256EncryptPublic {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		let ephemeral_sender_private = SecretKey::random(&mut OsRng);
		let ephemeral_sender_public: [u8; PUB_KEY_LEN_UNCOMPRESSED as usize] =
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
			&PrivPubOrSharedSecret::PrivPub {
				private: &ephemeral_sender_private,
				public: &self.public,
			},
			&sender_public_typed,
			&receiver_public_typed,
		)?;

		let nonce = {
			let random_bytes =
				crate::bytes_os_rng::<{ BITS_96_AS_BYTES as usize }>();
			*Nonce::from_slice(&random_bytes)
		};

		let aad = create_additional_associated_data(
			&sender_public_typed,
			&receiver_public_typed,
		)?;
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

	/// Decrypt a message encoded to this pair's public key.
	///
	/// This is designed to be used in scenarios where the private key is stored
	/// in enclave that computes a shared secret. That shared secret is then
	// used as input to this function.
	pub fn decrypt_from_shared_secret(
		&self,
		serialized_envelope: &[u8],
		shared_secret: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		let Envelope {
			nonce,
			ephemeral_sender_public: ephemeral_sender_public_bytes,
			encrypted_message,
		} = Envelope::try_from_slice(serialized_envelope)
			.map_err(|_| P256Error::FailedToDeserializeEnvelope)?;

		let nonce = Nonce::from_slice(&nonce);

		let sender_public_typed = SenderPublic(&ephemeral_sender_public_bytes);
		let receiver_encoded_point = self.public.to_encoded_point(false);
		let receiver_public_typed =
			ReceiverPublic(receiver_encoded_point.as_ref());

		let cipher = create_cipher(
			&PrivPubOrSharedSecret::SharedSecret { shared_secret },
			&sender_public_typed,
			&receiver_public_typed,
		)?;

		let aad = create_additional_associated_data(
			&sender_public_typed,
			&receiver_public_typed,
		)?;
		let payload = Payload { aad: &aad, msg: &encrypted_message };

		cipher
			.decrypt(nonce, payload)
			.map_err(|_| P256Error::AesGcm256DecryptError)
	}

	/// Serialize to SEC1 encoded point, not compressed.
	#[must_use]
	pub fn to_bytes(&self) -> Box<[u8]> {
		let sec1_encoded_point = self.public.to_encoded_point(false);
		sec1_encoded_point.to_bytes()
	}

	/// Deserialize from a SEC1 encoded point, not compressed.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			public: PublicKey::from_sec1_bytes(bytes)
				.map_err(|_| P256Error::FailedToReadPublicKey)?,
		})
	}
}

// Types for helper function parameters to help prevent fat finger mistakes.
struct SenderPublic<'a>(&'a [u8]);
struct ReceiverPublic<'a>(&'a [u8]);

/// This is the input into [`create_cipher`] for creating a shared secret.
/// It provides the option of either a) giving inputs for ECDH or b) providing
/// a shared secret directly.
///
/// This allows us to avoid duplicating logic for deriving the shared key.
enum PrivPubOrSharedSecret<'a> {
/// Inputs for using Diffie–Hellman to create a shared secret.
/// Note that this is not a classical private & public keypair.
/// Instead, the public key represents the remote party of the ECDH operation.
	PrivPub { private: &'a SecretKey, public: &'a PublicKey },
	/// This will be used as is as a shared secret.
	SharedSecret { shared_secret: &'a [u8] },
}

/// Helper function to create the `Aes256Gcm` cipher.
fn create_cipher(
	shared_secret: &PrivPubOrSharedSecret,
	ephemeral_sender_public: &SenderPublic,
	receiver_public: &ReceiverPublic,
) -> Result<Aes256Gcm, P256Error> {
	let shared_secret = match shared_secret {
		PrivPubOrSharedSecret::PrivPub { private, public } => {
			diffie_hellman(private.to_nonzero_scalar(), public.as_affine())
				.raw_secret_bytes()
				.to_vec()
		}
		PrivPubOrSharedSecret::SharedSecret { shared_secret } => {
			shared_secret.to_vec()
		}
	};

	// To help with entropy and add domain context, we do
	// `sender_public||receiver_public||shared_secret` as the pre-image for the
	// shared key.
	let pre_image: Vec<u8> = ephemeral_sender_public
		.0
		.iter()
		.chain(receiver_public.0)
		.chain(shared_secret.iter())
		.copied()
		.collect();

	let mut mac = <HmacSha512 as KeyInit>::new_from_slice(&pre_image[..])
		.expect("hmac can take a key of any size");
	mac.update(QOS_ENCRYPTION_HMAC_MESSAGE);
	let shared_key = mac.finalize().into_bytes();

	Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN])
		.map_err(|_| P256Error::FailedToCreateAes256GcmCipher)
}

/// Helper function to create the additional associated data (AAD). The data is
/// of the form
/// `sender_public||sender_public_len||receiver_public||receiver_public_len`.
///
/// Note that we append the length to each field as per NIST specs here: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf/>. See section 5.8.2.
fn create_additional_associated_data(
	ephemeral_sender_public: &SenderPublic,
	receiver_public: &ReceiverPublic,
) -> Result<Vec<u8>, P256Error> {
	let ephemeral_sender_len_int: u8 = ephemeral_sender_public
		.0
		.len()
		.try_into()
		.map_err(|_| P256Error::CannotCoerceLenToU8)?;
	let receiver_len_int: u8 = receiver_public
		.0
		.len()
		.try_into()
		.map_err(|_| P256Error::CannotCoerceLenToU8)?;

	let ephemeral_sender_len = &[ephemeral_sender_len_int];
	let receiver_public_len = &[receiver_len_int];

	let aad = ephemeral_sender_public
		.0
		.iter()
		.chain(ephemeral_sender_len)
		.chain(receiver_public.0)
		.chain(receiver_public_len)
		.copied()
		.collect();

	Ok(aad)
}

/// Envelope for holding an encrypted message and some metadata needed to
/// perform decryption.
#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SymmetricEnvelope {
	/// Nonce used by the cipher.
	pub nonce: [u8; BITS_96_AS_BYTES as usize],
	/// The ciphertext.
	pub encrypted_message: Vec<u8>,
}

/// Secret for performing encryption and decryption using a AES GCM 256 Cipher.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct AesGcm256Secret {
	secret: [u8; AES256_KEY_LEN],
}

impl AesGcm256Secret {
	/// Generate a secret
	#[must_use]
	pub fn generate() -> Self {
		Self { secret: bytes_os_rng::<AES256_KEY_LEN>() }
	}

	/// The secret as bytes.
	#[must_use]
	pub fn to_bytes(&self) -> &[u8; AES256_KEY_LEN] {
		&self.secret
	}

	/// Create [`Self`] from bytes.
	pub fn from_bytes(bytes: [u8; AES256_KEY_LEN]) -> Result<Self, P256Error> {
		Ok(Self { secret: bytes })
	}

	/// Encrypt the given `msg`.
	///
	/// Returns a serialized [`SymmetricEnvelope`].
	pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, P256Error> {
		let nonce = {
			let random_bytes = bytes_os_rng::<{ BITS_96_AS_BYTES as usize }>();
			*Nonce::from_slice(&random_bytes)
		};
		let payload = Payload { aad: AES_GCM_256_HMAC_SHA512_TAG, msg };

		let cipher = Aes256Gcm::new_from_slice(&self.secret)
			.expect("secret is a valid aes256 key len. qed.");
		let encrypted_message = cipher
			.encrypt(&nonce, payload)
			.map_err(|_| P256Error::AesGcm256EncryptError)?;

		let nonce = nonce
			.try_into()
			.map_err(|_| P256Error::FailedToCoerceNonceToIntendedLength)?;
		let envelope = SymmetricEnvelope { nonce, encrypted_message };
		envelope.try_to_vec().map_err(|_| P256Error::FailedToSerializeEnvelope)
	}

	/// Decrypt the given serialized [`SymmetricEnvelope`].
	///
	/// Returns the plaintext.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		let SymmetricEnvelope { nonce, encrypted_message } =
			SymmetricEnvelope::try_from_slice(serialized_envelope)
				.map_err(|_| P256Error::FailedToDeserializeEnvelope)?;

		let nonce = Nonce::from_slice(&nonce);
		let payload = Payload {
			aad: AES_GCM_256_HMAC_SHA512_TAG,
			msg: &encrypted_message,
		};

		let cipher = Aes256Gcm::new_from_slice(&self.secret)
			.expect("secret is a valid aes256 key len. qed.");
		cipher
			.decrypt(nonce, payload)
			.map_err(|_| P256Error::AesGcm256DecryptError)
	}
}

#[cfg(test)]
mod test_asymmetric {
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
		// byte and shift everything after, making the nonce too long.
		serialized_envelope.insert(BITS_96_AS_BYTES as usize, 0xff);

		assert_eq!(
			alice_pair.decrypt(&serialized_envelope).unwrap_err(),
			P256Error::FailedToDeserializeEnvelope
		);
	}

	#[test]
	fn public_key_roundtrip_bytes() {
		let alice_pair = P256EncryptPair::generate();
		let alice_public = alice_pair.public_key();

		let public_key_bytes = alice_public.to_bytes();
		let alice_public2 =
			P256EncryptPublic::from_bytes(&public_key_bytes).unwrap();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();

		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn private_key_roundtrip_bytes() {
		let pair = P256EncryptPair::generate();
		let raw_secret1 = pair.to_bytes();

		let pair2 = P256EncryptPair::from_bytes(&raw_secret1).unwrap();
		let raw_secret2 = pair2.to_bytes();

		assert_eq!(raw_secret1, raw_secret2);
	}
}

#[cfg(test)]
mod test_symmetric {
	use super::*;

	#[test]
	fn encrypt_decrypt_round_trip() {
		let plaintext = b"rust test message";

		let key = AesGcm256Secret::generate();

		let envelope = key.encrypt(plaintext).unwrap();
		let result = key.decrypt(&envelope).unwrap();

		assert_eq!(result, plaintext);
	}

	#[test]
	fn secret_roundtrip_bytes() {
		let key_original = AesGcm256Secret::generate();
		let bytes_original = key_original.to_bytes();

		let key_reconstructed =
			AesGcm256Secret::from_bytes(*bytes_original).unwrap();
		let bytes_reconstructed = key_reconstructed.to_bytes();

		assert!(key_original == key_reconstructed);
		assert_eq!(bytes_original, bytes_reconstructed);
	}

	#[test]
	fn tampered_nonce_errors() {
		let plaintext = b"rust test message";
		let key = AesGcm256Secret::generate();

		let envelope_bytes = key.encrypt(plaintext).unwrap();

		let mut envelope =
			SymmetricEnvelope::try_from_slice(&envelope_bytes).unwrap();
		if envelope.nonce[0] == u8::MAX {
			envelope.nonce[0] -= 1;
		} else {
			envelope.nonce[0] += 1;
		}
		let serialized_envelope = envelope.try_to_vec().unwrap();

		let err = key.decrypt(&serialized_envelope).unwrap_err();
		assert_eq!(err, P256Error::AesGcm256DecryptError,);
	}

	#[test]
	fn tampered_encrypted_payload_errors() {
		let plaintext = b"rust test message";
		let key = AesGcm256Secret::generate();

		let envelope_bytes = key.encrypt(plaintext).unwrap();

		let mut envelope =
			SymmetricEnvelope::try_from_slice(&envelope_bytes).unwrap();

		if envelope.encrypted_message[0] == u8::MAX {
			envelope.encrypted_message[0] -= 1;
		} else {
			envelope.encrypted_message[0] += 1;
		};
		let serialized_envelope = envelope.try_to_vec().unwrap();

		let err = key.decrypt(&serialized_envelope).unwrap_err();
		assert_eq!(err, P256Error::AesGcm256DecryptError,);
	}

	#[test]
	fn different_key_cannot_decrypt() {
		let plaintext = b"rust test message";
		let key = AesGcm256Secret::generate();
		let other_key = AesGcm256Secret::generate();

		let serialized_envelope = key.encrypt(plaintext).unwrap();

		let err = other_key.decrypt(&serialized_envelope).unwrap_err();
		assert_eq!(err, P256Error::AesGcm256DecryptError,);
	}
}
