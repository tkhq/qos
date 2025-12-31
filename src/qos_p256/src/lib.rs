//! Abstractions for authentication and encryption with NIST-P256.

use std::path::Path;

use encrypt::{AesGcm256Secret, AesKeyId};
use hkdf::Hkdf;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: u8 = 65;
const VERSION_LEN: usize = 8;

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
/// The first versioned format for quorum key secret.
pub const Q_KEY_V1: &[u8] = b"Q_KEY_V1";

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
	/// The length of the versioned secret is invalid.
	VersionedSecretInvalidLength,
	/// The length of the QuorumKeyId is invalid.
	QuorumKeyIdInvalidLength,
}

impl From<qos_hex::HexError> for P256Error {
	fn from(err: qos_hex::HexError) -> Self {
		match err {
			qos_hex::HexError::InvalidUtf8(_) => {
				P256Error::MasterSeedInvalidUtf8
			}
			_ => Self::QosHex(format!("{err:?}")),
		}
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
pub fn bytes_os_rng<const N: usize>() -> [u8; N] {
	let mut key = [0u8; N];
	OsRng.fill_bytes(&mut key);

	key
}

#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub enum VersionedSecret {
	/// Version 0, otherwise known as master seed.
	V0([u8; MASTER_SEED_LEN]),
	/// Version 1.
	V1([u8; 8 + 3 * 32]),
}

impl VersionedSecret {
	/// Create a versioned secret from raw bytes.
	pub fn from_bytes(secret: &[u8]) -> Result<Self, P256Error> {
		Ok(match &secret[..VERSION_LEN] {
			Q_KEY_V1 => VersionedSecret::V1(
				secret
					.try_into()
					.map_err(|_| P256Error::VersionedSecretInvalidLength)?,
			),
			_ => VersionedSecret::V0(
				secret
					.try_into()
					.map_err(|_| P256Error::VersionedSecretInvalidLength)?,
			),
		})
	}

	/// Encryption secret.
	pub fn encrypt_secret(&self) -> Result<[u8; P256_SECRET_LEN], P256Error> {
		match &self {
			Self::V0(ref s) => derive_secret(s, P256_ENCRYPT_DERIVE_PATH),
			Self::V1(ref s) => {
				let secrets = &s[VERSION_LEN..];
				secrets[32..2 * 32]
					.try_into()
					.map_err(|_| P256Error::VersionedSecretInvalidLength)
			}
		}
	}

	/// Signing secret.
	pub fn signing_secret(&self) -> Result<[u8; P256_SECRET_LEN], P256Error> {
		match &self {
			Self::V0(ref s) => derive_secret(s, P256_SIGN_DERIVE_PATH),
			Self::V1(ref s) => {
				let secrets = &s[VERSION_LEN..];
				secrets[..32]
					.try_into()
					.map_err(|_| P256Error::VersionedSecretInvalidLength)
			}
		}
	}

	/// AES GCM 256 symmetric encryption secret.
	fn aes_gcm_256_secret(&self) -> Result<[u8; P256_SECRET_LEN], P256Error> {
		match &self {
			Self::V0(ref s) => derive_secret(s, AES_GCM_256_PATH),
			Self::V1(ref s) => {
				let secrets = &s[VERSION_LEN..];
				secrets[2 * 32..3 * 32]
					.try_into()
					.map_err(|_| P256Error::VersionedSecretInvalidLength)
			}
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
	versioned_secret: VersionedSecret,
	aes_gcm_256_secret: AesGcm256Secret,
}

impl P256Pair {
	/// Generate a new private key using the OS randomness source.
	pub fn generate() -> Result<Self, P256Error> {
		let p256_encrypt_secret = bytes_os_rng::<MASTER_SEED_LEN>();
		let p256_sign_secret = bytes_os_rng::<MASTER_SEED_LEN>();
		let aes_gcm_secret = bytes_os_rng::<MASTER_SEED_LEN>();

		let versioned_secret_v1 = Q_KEY_V1
			.iter()
			.chain(p256_sign_secret.iter())
			.chain(p256_encrypt_secret.iter())
			.chain(aes_gcm_secret.iter())
			.copied()
			.collect::<Vec<u8>>()
			.try_into()
			// Impossible but we always stay defensive
			.map_err(|_| P256Error::VersionedSecretInvalidLength)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&p256_encrypt_secret,
			)?,
			sign_private: P256SignPair::from_bytes(&p256_sign_secret)?,
			versioned_secret: VersionedSecret::V1(versioned_secret_v1),
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

	/// Create self from a
	pub fn from_versioned_secret(secret: &[u8]) -> Result<Self, P256Error> {
		let versioned_secret = VersionedSecret::from_bytes(secret)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&versioned_secret.encrypt_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&versioned_secret.signing_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Get the versioned secret used to create this pair.
	#[must_use]
	pub fn to_versioned_secret(&self) -> &[u8] {
		match &self.versioned_secret {
			VersionedSecret::V0(ref s) => s,
			VersionedSecret::V1(ref s) => s,
		}
	}

	#[must_use]
	pub fn to_versioned_secret_hex(&self) -> Vec<u8> {
		qos_hex::encode_to_vec(self.to_versioned_secret())
	}

	/// Write the hex encoded versioned secret to a file.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), P256Error> {
		let mut hex_string = qos_hex::encode(self.to_versioned_secret());
		// Add a newline character for readability
		hex_string.push('\n');

		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			P256Error::IOError(format!(
				"failed to write master secret to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the hex encoded versioned secret from a file.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, P256Error> {
		let untrimmed_hex = std::fs::read_to_string(&path).map_err(|e| {
			P256Error::IOError(format!(
				"failed to read master seed from {}: {e}",
				path.as_ref().display()
			))
		})?;
		let hex = untrimmed_hex.trim();

		let versioned_secret = qos_hex::decode(hex).map_err(P256Error::from)?;

		Self::from_versioned_secret(&versioned_secret)
	}

	/// Get a reference to the underlying signing key. Useful for interoperation
	/// with other crypto abstractions.
	#[must_use]
	pub fn signing_key(&self) -> &p256::ecdsa::SigningKey {
		&self.sign_private.private
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
		qos_hex::encode_to_vec(&self.to_bytes())
	}

	/// Write the public key to a file encoded as a hex string.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), P256Error> {
		let hex_string = qos_hex::encode(&self.to_bytes());
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			P256Error::IOError(format!(
				"failed to write public key bytes to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the hex encoded public keys from a file.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, P256Error> {
		let hex_bytes = std::fs::read(&path).map_err(|e| {
			P256Error::IOError(format!(
				"failed to read public key bytes from {}: {e}",
				path.as_ref().display()
			))
		})?;

		let public_keys_bytes =
			qos_hex::decode_from_vec(hex_bytes).map_err(P256Error::from)?;

		Self::from_bytes(&public_keys_bytes)
	}

	/// Get a reference to the signing public key. Useful for interoperation
	/// with other crypto abstractions.
	#[must_use]
	pub fn signing_key(&self) -> &p256::ecdsa::VerifyingKey {
		&self.sign_public.public
	}
}

/// Quorum Key Identifier.
///
/// A compact identifier for a QOS key set consisting of:
/// - Encryption public key (SEC1 compressed, 33 bytes)
/// - Signing public key (SEC1 compressed, 33 bytes)
/// - AES key identifier (32 bytes)
///
/// Total size: 98 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumKeyId {
	/// Encryption public key in SEC1 compressed format
	encrypt_public: [u8; Self::COMPRESSED_PUB_KEY_LEN],
	/// Signing public key in SEC1 compressed format
	sign_public: [u8; Self::COMPRESSED_PUB_KEY_LEN],
	/// AES key identifier
	aes_key_id: [u8; AesKeyId::LEN],
}

impl QuorumKeyId {
	/// Length of a SEC1 compressed public key.
	pub const COMPRESSED_PUB_KEY_LEN: usize = 33;
	/// Total serialized length.
	pub const LEN: usize = Self::COMPRESSED_PUB_KEY_LEN * 2 + AesKeyId::LEN;

	/// Create a new `QuorumKeyId` from a `P256Pair`.
	#[must_use]
	pub fn from_pair(pair: &P256Pair) -> Self {
		let encrypt_public =
			pair.p256_encrypt_private.public_key().to_bytes_compressed();
		let sign_public = pair.sign_private.public_key().to_bytes_compressed();
		let aes_key_id = *pair.aes_gcm_256_secret.id().as_bytes();

		Self { encrypt_public, sign_public, aes_key_id }
	}

	/// Create a new `QuorumKeyId` from a `P256Public` and `AesKeyId`.
	#[must_use]
	pub fn from_public(public: &P256Public, aes_key_id: &AesKeyId) -> Self {
		let encrypt_public = public.encrypt_public.to_bytes_compressed();
		let sign_public = public.sign_public.to_bytes_compressed();
		let aes_key_id_bytes = *aes_key_id.as_bytes();

		Self { encrypt_public, sign_public, aes_key_id: aes_key_id_bytes }
	}

	/// Serialize to bytes.
	#[must_use]
	pub fn to_bytes(&self) -> [u8; Self::LEN] {
		let mut bytes = [0u8; Self::LEN];
		let mut offset = 0;

		bytes[offset..offset + Self::COMPRESSED_PUB_KEY_LEN]
			.copy_from_slice(&self.encrypt_public);
		offset += Self::COMPRESSED_PUB_KEY_LEN;

		bytes[offset..offset + Self::COMPRESSED_PUB_KEY_LEN]
			.copy_from_slice(&self.sign_public);
		offset += Self::COMPRESSED_PUB_KEY_LEN;

		bytes[offset..offset + AesKeyId::LEN].copy_from_slice(&self.aes_key_id);

		bytes
	}

	/// Deserialize from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		if bytes.len() != Self::LEN {
			return Err(P256Error::QuorumKeyIdInvalidLength);
		}

		let mut offset = 0;

		let encrypt_public: [u8; Self::COMPRESSED_PUB_KEY_LEN] = bytes
			[offset..offset + Self::COMPRESSED_PUB_KEY_LEN]
			.try_into()
			.map_err(|_| P256Error::QuorumKeyIdInvalidLength)?;
		offset += Self::COMPRESSED_PUB_KEY_LEN;

		let sign_public: [u8; Self::COMPRESSED_PUB_KEY_LEN] = bytes
			[offset..offset + Self::COMPRESSED_PUB_KEY_LEN]
			.try_into()
			.map_err(|_| P256Error::QuorumKeyIdInvalidLength)?;
		offset += Self::COMPRESSED_PUB_KEY_LEN;

		let aes_key_id: [u8; AesKeyId::LEN] = bytes
			[offset..offset + AesKeyId::LEN]
			.try_into()
			.map_err(|_| P256Error::QuorumKeyIdInvalidLength)?;

		// Validate that the public keys are valid SEC1 compressed points
		P256EncryptPublic::from_bytes_compressed(&encrypt_public)?;
		P256SignPublic::from_bytes_compressed(&sign_public)?;

		Ok(Self { encrypt_public, sign_public, aes_key_id })
	}

	/// Serialize to hex string.
	#[must_use]
	pub fn to_hex(&self) -> String {
		qos_hex::encode(&self.to_bytes())
	}

	/// Deserialize from hex string.
	pub fn from_hex(hex: &str) -> Result<Self, P256Error> {
		let bytes = qos_hex::decode(hex)?;
		Self::from_bytes(&bytes)
	}

	/// Get the encryption public key.
	pub fn encrypt_public(&self) -> Result<P256EncryptPublic, P256Error> {
		P256EncryptPublic::from_bytes_compressed(&self.encrypt_public)
	}

	/// Get the signing public key.
	pub fn sign_public(&self) -> Result<P256SignPublic, P256Error> {
		P256SignPublic::from_bytes_compressed(&self.sign_public)
	}

	/// Get the AES key identifier bytes.
	#[must_use]
	pub fn aes_key_id(&self) -> &[u8; AesKeyId::LEN] {
		&self.aes_key_id
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
		let master_seed = alice_pair.to_versioned_secret();

		let alice_pair2 = P256Pair::from_versioned_secret(master_seed).unwrap();

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

	mod v0_backwards_compatibility {
		use super::*;

		// Known V0 (master seed) test vector - this is the same key used in
		// qos_client/tests/mock/primary.secret.keep
		const V0_MASTER_SEED_HEX: &str =
			"c0e30ffefdad72ee214173f34af0faa57d58a1b733239e8100e903695bdd9a0c";
		const V0_PUBLIC_KEY_HEX: &str = "040f461f922c36cfdf16a65f3f370f106e33157d24608e1541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd2753cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025";
		const V0_EXPECTED_SIGNATURE: &str = "36c7f22c3831a32b8c8a9e823641e7df591c6e92848e7baa54f66d65963d15eaf02abbf5f01f99a8dddfe7a35453a4df486a708ffa3ef2d8159d4d0763f5ee89";
		const TEST_MESSAGE: &[u8] = b"test data";

		#[test]
		fn v0_secret_is_parsed_as_v0() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let versioned = VersionedSecret::from_bytes(&secret_bytes).unwrap();
			assert!(matches!(versioned, VersionedSecret::V0(_)));
		}

		#[test]
		fn v0_secret_produces_expected_public_key() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let pair = P256Pair::from_versioned_secret(&secret_bytes).unwrap();
			let public_key = pair.public_key();

			let expected_pub_bytes =
				qos_hex::decode(V0_PUBLIC_KEY_HEX).unwrap();
			assert_eq!(public_key.to_bytes(), expected_pub_bytes);
		}

		#[test]
		fn v0_secret_produces_expected_signature() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let pair = P256Pair::from_versioned_secret(&secret_bytes).unwrap();

			let signature = pair.sign(TEST_MESSAGE).unwrap();
			let expected_sig = qos_hex::decode(V0_EXPECTED_SIGNATURE).unwrap();
			assert_eq!(signature, expected_sig);
		}

		#[test]
		fn v0_secret_roundtrip_works() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let pair = P256Pair::from_versioned_secret(&secret_bytes).unwrap();
			let public_key = pair.public_key();

			// Test that we can serialize and deserialize the V0 secret
			let serialized = pair.to_versioned_secret();
			assert_eq!(serialized, secret_bytes.as_slice());

			let pair2 = P256Pair::from_versioned_secret(serialized).unwrap();

			// Verify signing still works after roundtrip
			let signature = pair2.sign(TEST_MESSAGE).unwrap();
			assert!(public_key.verify(TEST_MESSAGE, &signature).is_ok());
		}

		#[test]
		fn v0_secret_encrypt_decrypt_works() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let pair = P256Pair::from_versioned_secret(&secret_bytes).unwrap();
			let public_key = pair.public_key();

			let plaintext = b"backwards compatible encryption";
			let ciphertext = public_key.encrypt(plaintext).unwrap();
			let decrypted = pair.decrypt(&ciphertext).unwrap();

			assert_eq!(decrypted, plaintext);
		}

		#[test]
		fn v0_secret_aes_gcm_works() {
			let secret_bytes = qos_hex::decode(V0_MASTER_SEED_HEX).unwrap();
			let pair = P256Pair::from_versioned_secret(&secret_bytes).unwrap();

			let plaintext = b"backwards compatible aes gcm";
			let ciphertext = pair.aes_gcm_256_encrypt(plaintext).unwrap();
			let decrypted = pair.aes_gcm_256_decrypt(&ciphertext).unwrap();

			assert_eq!(decrypted, plaintext);
		}
	}

	mod quorum_key_id {
		use super::*;

		#[test]
		fn quorum_key_id_has_correct_length() {
			assert_eq!(QuorumKeyId::LEN, 98);
		}

		#[test]
		fn from_pair_roundtrip() {
			let pair = P256Pair::generate().unwrap();
			let key_id = QuorumKeyId::from_pair(&pair);

			let bytes = key_id.to_bytes();
			assert_eq!(bytes.len(), QuorumKeyId::LEN);

			let key_id2 = QuorumKeyId::from_bytes(&bytes).unwrap();
			assert_eq!(key_id, key_id2);
		}

		#[test]
		fn from_public_roundtrip() {
			let pair = P256Pair::generate().unwrap();
			let public = pair.public_key();
			let aes_key_id = pair.aes_gcm_256_secret.id();

			let key_id = QuorumKeyId::from_public(&public, &aes_key_id);

			let bytes = key_id.to_bytes();
			let key_id2 = QuorumKeyId::from_bytes(&bytes).unwrap();
			assert_eq!(key_id, key_id2);
		}

		#[test]
		fn hex_roundtrip() {
			let pair = P256Pair::generate().unwrap();
			let key_id = QuorumKeyId::from_pair(&pair);

			let hex = key_id.to_hex();
			assert_eq!(hex.len(), QuorumKeyId::LEN * 2);

			let key_id2 = QuorumKeyId::from_hex(&hex).unwrap();
			assert_eq!(key_id, key_id2);
		}

		#[test]
		fn invalid_length_rejected() {
			let too_short = vec![0u8; QuorumKeyId::LEN - 1];
			let too_long = vec![0u8; QuorumKeyId::LEN + 1];

			assert_eq!(
				QuorumKeyId::from_bytes(&too_short).unwrap_err(),
				P256Error::QuorumKeyIdInvalidLength
			);
			assert_eq!(
				QuorumKeyId::from_bytes(&too_long).unwrap_err(),
				P256Error::QuorumKeyIdInvalidLength
			);
		}

		#[test]
		fn can_recover_public_keys() {
			let pair = P256Pair::generate().unwrap();
			let public = pair.public_key();
			let key_id = QuorumKeyId::from_pair(&pair);

			let recovered_encrypt = key_id.encrypt_public().unwrap();
			let recovered_sign = key_id.sign_public().unwrap();

			// Verify recovered keys work for encryption/verification
			let plaintext = b"test message";
			let ciphertext = recovered_encrypt.encrypt(plaintext).unwrap();
			let decrypted = pair.decrypt(&ciphertext).unwrap();
			assert_eq!(decrypted, plaintext);

			let signature = pair.sign(plaintext).unwrap();
			assert!(recovered_sign.verify(plaintext, &signature).is_ok());

			// Verify they match the original
			assert_eq!(
				recovered_encrypt.to_bytes_compressed(),
				public.encrypt_public.to_bytes_compressed()
			);
			assert_eq!(
				recovered_sign.to_bytes_compressed(),
				public.sign_public.to_bytes_compressed()
			);
		}

		#[test]
		fn from_pair_and_from_public_produce_same_result() {
			let pair = P256Pair::generate().unwrap();
			let public = pair.public_key();
			let aes_key_id = pair.aes_gcm_256_secret.id();

			let key_id_from_pair = QuorumKeyId::from_pair(&pair);
			let key_id_from_public =
				QuorumKeyId::from_public(&public, &aes_key_id);

			assert_eq!(key_id_from_pair, key_id_from_public);
		}

		#[test]
		fn different_pairs_produce_different_key_ids() {
			let pair1 = P256Pair::generate().unwrap();
			let pair2 = P256Pair::generate().unwrap();

			let key_id1 = QuorumKeyId::from_pair(&pair1);
			let key_id2 = QuorumKeyId::from_pair(&pair2);

			assert_ne!(key_id1, key_id2);
		}
	}
}
