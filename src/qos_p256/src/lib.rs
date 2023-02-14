//! Abstractions for authentication and encryption with NIST-P256.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::path::Path;

use encrypt::AesGcm256Secret;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: u8 = 65;

/// Master seed derive path for encryption secret
pub const P256_ENCRYPT_DERIVE_PATH: &[u8] = b"qos_p256_encrypt";
/// Master seed derive path for signing secret
pub const P256_SIGN_DERIVE_PATH: &[u8] = b"qos_p256_sign";
/// Master seed derive path for aes gcm
pub const AES_GCM_256_PATH: &[u8] = b"qos_aes_gcm_encrypt";
/// Length of a p256 secret seed.
pub const P256_SECRET_LEN: usize = 32;
/// Length of the master seed.
pub const MASTER_SEED_LEN: usize = 32;

pub mod encrypt;
pub mod sign;

/// Errors for qos P256.
#[derive(
	Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum P256Error {
	/// Hex encoding error.
	QosHex(String),
	/// IO error
	IOError(String),
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
	/// Signature could not be de-serialized.
	FailedToDeserializeSignature,
	/// The signature could not be verified against the given message and
	/// public key.
	FailedSignatureVerification,
	/// The raw bytes could not be interpreted as a P256 secret.
	FailedToReadSecret,
	/// The raw bytes could not be interpreted as SEC1 encoded point
	/// uncompressed.
	FailedToReadPublicKey,
	/// The  public key is too long to be valid.
	EncodedPublicKeyTooLong,
	/// The public key is too short to be valid.
	EncodedPublicKeyTooShort,
	/// Error'ed while running HKDF expansion
	HkdfExpansionFailed,
	/// Master seed was not stored as valid utf8 encoding.
	MasterSeedInvalidUtf8,
	/// Master seed was not the correct length.
	MasterSeedInvalidLength,
	/// Failed to convert a len (usize) to a u8. This is an internal error and
	/// the code has a bug.
	CannotCoerceLenToU8,
}

impl From<qos_hex::HexError> for P256Error {
	fn from(err: qos_hex::HexError) -> Self {
		Self::QosHex(format!("{err:?}"))
	}
}

/// Helper function to derive a secret from a master seed.
pub fn derive_secret(
	seed: &[u8; MASTER_SEED_LEN],
	derive_path: &[u8],
) -> Result<[u8; P256_SECRET_LEN], P256Error> {
	let hk = Hkdf::<Sha512>::new(Some(derive_path), seed);

	let mut buf = [0u8; P256_SECRET_LEN];
	hk.expand(&[], &mut buf).map_err(|_| P256Error::HkdfExpansionFailed)?;

	Ok(buf)
}

/// Helper function to generate a `N` length byte buffer.
#[must_use]
pub fn non_zero_bytes_os_rng<const N: usize>() -> [u8; N] {
	loop {
		let mut key = [0u8; N];
		OsRng.fill_bytes(&mut key);

		if key.iter().all(|bit| *bit == 0) {
			// try again if we got all zeros
		} else {
			return key;
		}
	}
}

/// P256 private key pair for signing and encryption. Internally this uses a
/// separate secret for signing and encryption.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct P256Pair {
	p256_encrypt_private: P256EncryptPair,
	sign_private: P256SignPair,
	master_seed: [u8; MASTER_SEED_LEN],
	aes_gcm_256_secret: AesGcm256Secret,
}

impl P256Pair {
	/// Generate a new private key using the OS randomness source.
	pub fn generate() -> Result<Self, P256Error> {
		let master_seed = non_zero_bytes_os_rng::<MASTER_SEED_LEN>();

		let p256_encrypt_secret =
			derive_secret(&master_seed, P256_ENCRYPT_DERIVE_PATH)?;
		let p256_sign_secret =
			derive_secret(&master_seed, P256_SIGN_DERIVE_PATH)?;
		let aes_gcm_secret = derive_secret(&master_seed, AES_GCM_256_PATH)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&p256_encrypt_secret,
			)?,
			sign_private: P256SignPair::from_bytes(&p256_sign_secret)?,
			master_seed,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(aes_gcm_secret)?,
		})
	}

	/// Encrypt the given `msg` with the symmetric encryption secret.
	pub fn aes_gcm_256_encrypt(
		&self,
		msg: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		self.aes_gcm_256_secret.encrypt(msg)
	}

	/// Decrypt a message with the symmetric encryption secret.
	pub fn aes_gcm_256_decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		self.aes_gcm_256_secret.decrypt(serialized_envelope)
	}

	/// Decrypt a message encoded to this pair's public key.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, P256Error> {
		self.p256_encrypt_private.decrypt(serialized_envelope)
	}

	/// Sign the message and return the raw signature.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		self.sign_private.sign(message)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> P256Public {
		P256Public {
			encrypt_public: self.p256_encrypt_private.public_key(),
			sign_public: self.sign_private.public_key(),
		}
	}

	/// Create `Self` from a master seed.
	pub fn from_master_seed(
		master_seed: &[u8; MASTER_SEED_LEN],
	) -> Result<Self, P256Error> {
		let encrypt_secret =
			derive_secret(master_seed, P256_ENCRYPT_DERIVE_PATH)?;
		let sign_secret = derive_secret(master_seed, P256_SIGN_DERIVE_PATH)?;
		let aes_gcm_256_encrypt = derive_secret(master_seed, AES_GCM_256_PATH)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(&encrypt_secret)?,
			sign_private: P256SignPair::from_bytes(&sign_secret)?,
			master_seed: *master_seed,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				aes_gcm_256_encrypt,
			)?,
		})
	}

	/// Get the raw master seed used to create this pair.
	#[must_use]
	pub fn to_master_seed(&self) -> &[u8; MASTER_SEED_LEN] {
		&self.master_seed
	}

	/// Convert to hex bytes.
	#[must_use]
	pub fn to_master_seed_hex(&self) -> Vec<u8> {
		let hex_string = qos_hex::encode(&self.master_seed);
		hex_string.as_bytes().to_vec()
	}

	/// Write the raw master seed to file as hex encoded.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), P256Error> {
		let hex_string = qos_hex::encode(&self.master_seed);
		std::fs::write(path, hex_string.as_bytes()).map_err(|e| {
			P256Error::IOError(format!("failed to write master secret {e}"))
		})
	}

	/// Read the raw, hex encoded master from a file.
	// TODO(zeke): implement utils that go to/from bytes so we can avoid string
	// serialization. https://github.com/tkhq/qos/issues/153.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, P256Error> {
		let hex_bytes = std::fs::read(path).map_err(|e| {
			P256Error::IOError(format!("failed to read master seed: {e}"))
		})?;

		let hex_string = String::from_utf8(hex_bytes)
			.map_err(|_| P256Error::MasterSeedInvalidUtf8)?;
		let hex_string = hex_string.trim();

		let master_seed = qos_hex::decode(hex_string)?;
		let master_seed: [u8; MASTER_SEED_LEN] = master_seed
			.try_into()
			.map_err(|_| P256Error::MasterSeedInvalidLength)?;
		Self::from_master_seed(&master_seed)
	}
}

/// P256 public key for signing and encryption. Internally this uses
/// separate public keys for signing and encryption.
#[derive(Clone, PartialEq, Eq)]
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

	/// Serialize each public key as a SEC1 encoded point, not compressed.
	/// Encodes as `encrypt_public||sign_public`.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		self.encrypt_public
			.to_bytes()
			.iter()
			.chain(self.sign_public.to_bytes().iter())
			.copied()
			.collect()
	}

	/// Deserialize each public key from a SEC1 encoded point, not compressed.
	/// Expects encoding as `encrypt_public||sign_public`.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		if bytes.len() > PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(P256Error::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(P256Error::EncodedPublicKeyTooShort);
		}

		let (encrypt_bytes, sign_bytes) =
			bytes.split_at(PUB_KEY_LEN_UNCOMPRESSED as usize);

		Ok(Self {
			encrypt_public: P256EncryptPublic::from_bytes(encrypt_bytes)
				.map_err(|_| P256Error::FailedToReadPublicKey)?,
			sign_public: P256SignPublic::from_bytes(sign_bytes)
				.map_err(|_| P256Error::FailedToReadPublicKey)?,
		})
	}

	/// Convert to hex bytes.
	#[must_use]
	pub fn to_hex_bytes(&self) -> Vec<u8> {
		let hex_string = qos_hex::encode(&self.to_bytes());
		hex_string.as_bytes().to_vec()
	}

	/// Write the public key to a file encoded as a hex string.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), P256Error> {
		let hex_string = qos_hex::encode(&self.to_bytes());
		std::fs::write(path, hex_string.as_bytes()).map_err(|e| {
			P256Error::IOError(format!("failed to write master secret: {e}"))
		})
	}

	/// Read the hex encoded public keys from a file.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, P256Error> {
		let hex_bytes = std::fs::read(path).map_err(|e| {
			P256Error::IOError(format!("failed to read master seed: {e}"))
		})?;

		let hex_string = String::from_utf8(hex_bytes)
			.map_err(|_| P256Error::MasterSeedInvalidUtf8)?;
		let hex_string = hex_string.trim();

		let public_keys_bytes = qos_hex::decode(hex_string)?;

		Self::from_bytes(&public_keys_bytes)
	}
}

#[cfg(test)]
mod test {
	use qos_test_primitives::PathWrapper;

	use super::*;

	#[test]
	fn signatures_are_deterministic() {
		let message = b"a message to authenticate";

		let pair = P256Pair::generate().unwrap();
		(0..100)
			.map(|_| pair.sign(message).unwrap())
			.collect::<Vec<_>>()
			.windows(2)
			.for_each(|slice| assert_eq!(slice[0], slice[1]));
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = P256Pair::generate().unwrap();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = P256Pair::generate().unwrap();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = P256Pair::generate().unwrap().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			P256Error::FailedSignatureVerification
		);
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = P256Pair::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = P256Pair::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let bob_pair = P256Pair::generate().unwrap();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			P256Error::AesGcm256DecryptError
		);
	}

	#[test]
	fn public_key_bytes_roundtrip() {
		let alice_pair = P256Pair::generate().unwrap();
		let alice_public = alice_pair.public_key();
		let alice_public_bytes = alice_public.to_bytes();

		assert_eq!(
			alice_public_bytes.len(),
			PUB_KEY_LEN_UNCOMPRESSED as usize * 2
		);

		let alice_public2 =
			P256Public::from_bytes(&alice_public_bytes).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();
		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair.sign(message).unwrap();
		assert!(alice_public2.verify(message, &signature).is_ok());
	}

	#[test]
	fn public_key_to_file_roundtrip() {
		let path: PathWrapper =
			"/tmp/public_key_to_file_roundtrip.secret".into();
		let alice_pair = P256Pair::generate().unwrap();
		let alice_public = alice_pair.public_key();

		alice_public.to_hex_file(&*path).unwrap();

		let alice_public2 = P256Public::from_hex_file(&*path).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();
		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair.sign(message).unwrap();
		assert!(alice_public2.verify(message, &signature).is_ok());
	}

	#[test]
	fn master_seed_bytes_roundtrip() {
		let alice_pair = P256Pair::generate().unwrap();
		let public_key = alice_pair.public_key();
		let master_seed = alice_pair.to_master_seed();

		let alice_pair2 = P256Pair::from_master_seed(master_seed).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = public_key.encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());
	}

	#[test]
	fn master_seed_to_file_round_trip() {
		let path: PathWrapper =
			"/tmp/master_seed_to_file_round_trip.secret".into();

		let alice_pair = P256Pair::generate().unwrap();
		alice_pair.to_hex_file(&*path).unwrap();

		let alice_pair2 = P256Pair::from_hex_file(&*path).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope =
			alice_pair.public_key().encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(alice_pair.public_key().verify(message, &signature).is_ok());
	}

	mod aes_gcm_256 {
		use super::*;

		#[test]
		fn encrypt_decrypt_round_trip() {
			let plaintext = b"rust test message";

			let key = P256Pair::generate().unwrap();

			let envelope = key.aes_gcm_256_encrypt(plaintext).unwrap();
			let result = key.aes_gcm_256_decrypt(&envelope).unwrap();

			assert_eq!(result, plaintext);
		}

		#[test]
		fn different_key_cannot_decrypt() {
			let plaintext = b"rust test message";
			let key = P256Pair::generate().unwrap();
			let other_key = P256Pair::generate().unwrap();

			let serialized_envelope =
				key.aes_gcm_256_encrypt(plaintext).unwrap();

			let err = other_key
				.aes_gcm_256_decrypt(&serialized_envelope)
				.unwrap_err();
			assert_eq!(err, P256Error::AesGcm256DecryptError,);
		}
	}
}
