#![doc = include_str!("../SPEC.md")]

use std::path::Path;

use encrypt::AesGcm256Secret;
use hkdf::Hkdf;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: u8 = 65;
/// Leading byte to indicate a secret is version 1.
const SECRET_V1: u8 = 0x01;
const QUORUM_KEY_ID_V1: u8 = 0x01;
const AES_GCM_256_KEY_ID_INFO: &[u8] = b"AES_GCM_256_KEY_ID";

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
pub enum QosKeySetError {
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

impl From<qos_hex::HexError> for QosKeySetError {
	fn from(err: qos_hex::HexError) -> Self {
		match err {
			qos_hex::HexError::InvalidUtf8(_) => {
				QosKeySetError::MasterSeedInvalidUtf8
			}
			_ => Self::QosHex(format!("{err:?}")),
		}
	}
}

/// Helper function to derive a secret from a master seed.
pub fn derive_secret(
	seed: &[u8; MASTER_SEED_LEN],
	derive_path: &[u8],
) -> Result<[u8; P256_SECRET_LEN], QosKeySetError> {
	let hk = Hkdf::<Sha512>::new(Some(derive_path), seed);

	let mut buf = [0u8; P256_SECRET_LEN];
	hk.expand(&[], &mut buf)
		.map_err(|_| QosKeySetError::HkdfExpansionFailed)?;

	Ok(buf)
}

/// Helper function to generate a `N` length byte buffer.
#[must_use]
pub fn bytes_os_rng<const N: usize>() -> [u8; N] {
	let mut key = [0u8; N];
	OsRng.fill_bytes(&mut key);

	key
}

/// A secret to create a [`QosKeySet`]
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub enum VersionedSecret {
	V0([u8; 32]),
	V1([u8; 97]),
}

impl VersionedSecret {
	/// Parse a secret from raw bytes.
	fn from_bytes(bytes: &[u8]) -> Result<Self, QosKeySetError> {
		if let Ok(array) = TryInto::<[u8; 97]>::try_into(bytes) {
			// Validations from spec `PARSE_SECRET`
			if array[0] == SECRET_V1 {
				let this = Self::V1(array);

				// Validate hpke_secret and sign_secret are valid P256 scalars
				P256SignPair::from_bytes(&this.hpke_secret()?)?;
				P256EncryptPair::from_bytes(&this.sign_secret()?)?;

				return Ok(this);
			}
		} else if let Ok(array) = TryInto::<[u8; 32]>::try_into(bytes) {
			return Ok(Self::V0(array));
		}

		Err(QosKeySetError::FailedToReadSecret)
	}

	/// Get the secret bytes
	pub fn as_bytes(&self) -> &[u8] {
		match self {
			Self::V0(ref b) => b,
			Self::V1(ref b) => b,
		}
	}

	/// Get the HPKE (encryption) secret bytes.
	pub fn hpke_secret(&self) -> Result<[u8; 32], QosKeySetError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, P256_ENCRYPT_DERIVE_PATH),
			Self::V1(bytes) => {
				Ok(bytes[1..33].try_into().expect("exactly 32 bytes. qed."))
			}
		}
	}

	/// Get the signing secret bytes.
	pub fn sign_secret(&self) -> Result<[u8; 32], QosKeySetError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, P256_SIGN_DERIVE_PATH),
			Self::V1(bytes) => {
				Ok(bytes[33..65].try_into().expect("exactly 32 bytes. qed."))
			}
		}
	}

	/// Get the AES-GCM-256 symmetric encryption secret bytes.
	pub fn aes_gcm_256_secret(&self) -> Result<[u8; 32], QosKeySetError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, AES_GCM_256_PATH),
			Self::V1(bytes) => {
				Ok(bytes[65..].try_into().expect("exactly 32 bytes. qed."))
			}
		}
	}
}

/// P256 private key pair for signing and encryption. Internally this uses a
/// separate secret for signing and encryption.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct QosKeySet {
	p256_encrypt_private: P256EncryptPair,
	sign_private: P256SignPair,
	aes_gcm_256_secret: AesGcm256Secret,
	versioned_secret: VersionedSecret,
}

impl QosKeySet {
	/// Generate a new private key using the OS randomness source.
	pub fn generate() -> Result<Self, QosKeySetError> {
		let mut bytes = bytes_os_rng::<97>();
		bytes[0] = SECRET_V1;
		let versioned_secret = VersionedSecret::from_bytes(&bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Generate a key set from a V0 secret.
	pub fn generate_v0() -> Result<Self, QosKeySetError> {
		// V0 secrets are 32 bytes
		let bytes = bytes_os_rng::<32>();
		let versioned_secret = VersionedSecret::from_bytes(&bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Encrypt the given `msg` with the symmetric encryption secret.
	pub fn aes_gcm_256_encrypt(
		&self,
		msg: &[u8],
	) -> Result<Vec<u8>, QosKeySetError> {
		self.aes_gcm_256_secret.encrypt(msg)
	}

	/// Decrypt a message with the symmetric encryption secret.
	pub fn aes_gcm_256_decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, QosKeySetError> {
		self.aes_gcm_256_secret.decrypt(serialized_envelope)
	}

	/// Decrypt a message encoded to this pair's public key.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, QosKeySetError> {
		self.p256_encrypt_private.decrypt(serialized_envelope)
	}

	/// Sign the message and return the raw signature.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, QosKeySetError> {
		self.sign_private.sign(message)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> QosKeySetV0Public {
		QosKeySetV0Public {
			encrypt_public: self.p256_encrypt_private.public_key(),
			sign_public: self.sign_private.public_key(),
		}
	}

	/// Create `Self` from the raw bytes of the versioned secret.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, QosKeySetError> {
		let versioned_secret = VersionedSecret::from_bytes(bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Get the raw versioned secret used to create this key set.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.versioned_secret.as_bytes()
	}

	/// Get the hex encoded versioned secret used to create this key set.
	#[must_use]
	pub fn to_hex(&self) -> Vec<u8> {
		qos_hex::encode_to_vec(self.versioned_secret.as_bytes())
	}

	/// Write the raw master seed to file as hex encoded.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), QosKeySetError> {
		let hex_string = qos_hex::encode(self.versioned_secret.as_bytes());
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			QosKeySetError::IOError(format!(
				"failed to write master secret to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the raw, hex encoded master from a file.
	pub fn from_hex_file<P: AsRef<Path>>(
		path: P,
	) -> Result<Self, QosKeySetError> {
		let hex = std::fs::read_to_string(&path).map_err(|e| {
			QosKeySetError::IOError(format!(
				"failed to read master seed from {}: {e}",
				path.as_ref().display()
			))
		})?;
		let hex = hex.trim();

		let versioned_secret =
			qos_hex::decode(hex).map_err(QosKeySetError::from)?;
		Self::from_bytes(&versioned_secret)
	}

	/// Get a reference to the underlying signing key. Useful for interoperation
	/// with other crypto abstractions.
	#[must_use]
	pub fn signing_key(&self) -> &p256::ecdsa::SigningKey {
		&self.sign_private.private
	}

	/// Get a reference to the underlying versioned secret.
	pub fn versioned_secret(&self) -> &VersionedSecret {
		&self.versioned_secret
	}

	/// Compute the quorum key ID for this key set.
	pub fn quorum_key_id(&self) -> Result<QuorumKeyId, QosKeySetError> {
		let key_id =
			aes_gcm_256_key_id(&self.versioned_secret.aes_gcm_256_secret()?)?;
		QuorumKeyId::from_parts(
			&self.p256_encrypt_private.public_key().to_bytes(),
			&self.sign_private.public_key().to_bytes(),
			&key_id,
		)
	}
}

/// P256 public key for signing and encryption. Internally this uses
/// separate public keys for signing and encryption.
#[derive(Clone, PartialEq, Eq)]
pub struct QosKeySetV0Public {
	encrypt_public: P256EncryptPublic,
	sign_public: P256SignPublic,
}

impl QosKeySetV0Public {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, QosKeySetError> {
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
	) -> Result<(), QosKeySetError> {
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
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, QosKeySetError> {
		if bytes.len() > PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(QosKeySetError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(QosKeySetError::EncodedPublicKeyTooShort);
		}

		let (encrypt_bytes, sign_bytes) =
			bytes.split_at(PUB_KEY_LEN_UNCOMPRESSED as usize);

		Ok(Self {
			encrypt_public: P256EncryptPublic::from_bytes(encrypt_bytes)
				.map_err(|_| QosKeySetError::FailedToReadPublicKey)?,
			sign_public: P256SignPublic::from_bytes(sign_bytes)
				.map_err(|_| QosKeySetError::FailedToReadPublicKey)?,
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
	) -> Result<(), QosKeySetError> {
		let hex_string = format!("{}\n", qos_hex::encode(&self.to_bytes()));
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			QosKeySetError::IOError(format!(
				"failed to write public key bytes to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the hex encoded public keys from a file.
	pub fn from_hex_file<P: AsRef<Path>>(
		path: P,
	) -> Result<Self, QosKeySetError> {
		let hex = std::fs::read_to_string(&path).map_err(|e| {
			QosKeySetError::IOError(format!(
				"failed to read public key bytes from {}: {e}",
				path.as_ref().display()
			))
		})?;
		let hex = hex.trim();

		let public_keys_bytes =
			qos_hex::decode(hex).map_err(QosKeySetError::from)?;

		Self::from_bytes(&public_keys_bytes)
	}

	/// Get a reference to the signing public key. Useful for interoperation
	/// with other crypto abstractions.
	#[must_use]
	pub fn signing_key(&self) -> &p256::ecdsa::VerifyingKey {
		&self.sign_public.public
	}
}

/// AES_GCM_256_KEY_ID as per spec.
pub fn aes_gcm_256_key_id(secret: &[u8]) -> Result<[u8; 32], QosKeySetError> {
	let prk = Hkdf::<sha2::Sha256>::new(None, secret);

	let mut buf = [0u8; 32];
	prk.expand(AES_GCM_256_KEY_ID_INFO, &mut buf)
		.map_err(|_| QosKeySetError::HkdfExpansionFailed)?;

	Ok(buf)
}

/// Identifier for a quorum key set containing public keys and a derived key ID.
pub struct QuorumKeyId {
	hpke_public: [u8; 65],
	sign_public: [u8; 65],
	aes_gcm_256_key_id: [u8; 32],
}

impl QuorumKeyId {
	fn from_parts(
		hpke_public: &[u8],
		sign_public: &[u8],
		aes_gcm_256_key_id: &[u8],
	) -> Result<Self, QosKeySetError> {
		let hpke_public = hpke_public
			.try_into()
			.map_err(|_| QosKeySetError::FailedToReadPublicKey)?;
		let sign_public = sign_public
			.try_into()
			.map_err(|_| QosKeySetError::FailedToReadPublicKey)?;
		let aes_gcm_256_key_id = aes_gcm_256_key_id
			.try_into()
			.map_err(|_| QosKeySetError::FailedToReadPublicKey)?;

		Ok(Self { hpke_public, sign_public, aes_gcm_256_key_id })
	}

	/// Serialize to bytes as `version || hpke_public || sign_public || aes_gcm_256_key_id`.
	pub fn to_bytes(&self) -> [u8; 163] {
		let mut bytes = [0u8; 163];
		bytes[0] = QUORUM_KEY_ID_V1;
		bytes[1..66].copy_from_slice(&self.hpke_public);
		bytes[66..131].copy_from_slice(&self.sign_public);
		bytes[131..163].copy_from_slice(&self.aes_gcm_256_key_id);
		bytes
	}

	/// Compute the SHA-256 fingerprint of this quorum key ID.
	pub fn fingerprint(&self) -> [u8; 32] {
		qos_crypto::sha_256(&self.to_bytes())
	}
}

#[cfg(test)]
mod test {
	use qos_test_primitives::PathWrapper;

	use super::*;

	#[test]
	fn signatures_are_deterministic() {
		let message = b"a message to authenticate";

		let pair = QosKeySet::generate().unwrap();
		(0..100)
			.map(|_| pair.sign(message).unwrap())
			.collect::<Vec<_>>()
			.windows(2)
			.for_each(|slice| assert_eq!(slice[0], slice[1]));
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = QosKeySet::generate().unwrap();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = QosKeySet::generate().unwrap();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = QosKeySet::generate().unwrap().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			QosKeySetError::FailedSignatureVerification
		);
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = QosKeySet::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = QosKeySet::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let bob_pair = QosKeySet::generate().unwrap();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			QosKeySetError::AesGcm256DecryptError
		);
	}

	#[test]
	fn public_key_bytes_roundtrip() {
		let alice_pair = QosKeySet::generate().unwrap();
		let alice_public = alice_pair.public_key();
		let alice_public_bytes = alice_public.to_bytes();

		assert_eq!(
			alice_public_bytes.len(),
			PUB_KEY_LEN_UNCOMPRESSED as usize * 2
		);

		let alice_public2 =
			QosKeySetV0Public::from_bytes(&alice_public_bytes).unwrap();

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
		let alice_pair = QosKeySet::generate().unwrap();
		let alice_public = alice_pair.public_key();

		alice_public.to_hex_file(&*path).unwrap();

		let alice_public2 = QosKeySetV0Public::from_hex_file(&*path).unwrap();

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
		let alice_pair = QosKeySet::generate().unwrap();
		let public_key = alice_pair.public_key();
		let master_seed = alice_pair.versioned_secret().as_bytes();

		let alice_pair2 = QosKeySet::from_bytes(master_seed).unwrap();

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

		let alice_pair = QosKeySet::generate().unwrap();
		alice_pair.to_hex_file(&*path).unwrap();

		let alice_pair2 = QosKeySet::from_hex_file(&*path).unwrap();

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

			let key = QosKeySet::generate().unwrap();

			let envelope = key.aes_gcm_256_encrypt(plaintext).unwrap();
			let result = key.aes_gcm_256_decrypt(&envelope).unwrap();

			assert_eq!(result, plaintext);
		}

		#[test]
		fn different_key_cannot_decrypt() {
			let plaintext = b"rust test message";
			let key = QosKeySet::generate().unwrap();
			let other_key = QosKeySet::generate().unwrap();

			let serialized_envelope =
				key.aes_gcm_256_encrypt(plaintext).unwrap();

			let err = other_key
				.aes_gcm_256_decrypt(&serialized_envelope)
				.unwrap_err();
			assert_eq!(err, QosKeySetError::AesGcm256DecryptError,);
		}
	}
}
