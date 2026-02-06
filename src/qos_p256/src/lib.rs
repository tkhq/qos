#![doc = include_str!("../SPEC.md")]

use std::path::Path;

use encrypt::AesGcm256Secret;
use hkdf::Hkdf;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
	encrypt::{P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
};

const PUB_KEY_LEN_UNCOMPRESSED: u8 = 65;
/// Leading byte to indicate a secret is version 1.
const SECRET_V1: u8 = 0x01;
/// Leading byte to indicate a key ID is version 1.
const QUORUM_KEY_ID_V1: u8 = 0x01;
/// HKDF info for deriving a AES GCM 256 key ID.
const AES_GCM_256_KEY_ID_INFO: &[u8] = b"AES_GCM_256_KEY_ID";

/// Master seed derive path for encryption secret
pub const P256_ENCRYPT_DERIVE_PATH: &[u8] = b"qos_p256_encrypt";
/// Master seed derive path for signing secret
pub const P256_SIGN_DERIVE_PATH: &[u8] = b"qos_p256_sign";
/// Master seed derive path for aes gcm
pub const AES_GCM_256_PATH: &[u8] = b"qos_aes_gcm_encrypt";
/// Length of a p256 secret seed.
pub const P256_SECRET_LEN: usize = 32;
/// Length of the master seed. Otherwise known as the V0 versioned secret.
pub const MASTER_SEED_LEN: usize = 32;

pub mod encrypt;
pub mod sign;

/// Errors for qos P256.
#[derive(
	Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum QuorumKeyError {
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

impl From<qos_hex::HexError> for QuorumKeyError {
	fn from(err: qos_hex::HexError) -> Self {
		match err {
			qos_hex::HexError::InvalidUtf8(_) => {
				QuorumKeyError::MasterSeedInvalidUtf8
			}
			_ => Self::QosHex(format!("{err:?}")),
		}
	}
}

/// Helper function to derive a secret from a master seed.
pub fn derive_secret(
	seed: &[u8; MASTER_SEED_LEN],
	derive_path: &[u8],
) -> Result<Zeroizing<[u8; P256_SECRET_LEN]>, QuorumKeyError> {
	// Using the path as the salt parameter is non-standard and is an historical
	// implementation artifact kept for v0 compatibility. While non-standard this
	// is still safe.
	let hk = Hkdf::<Sha512>::new(Some(derive_path), seed);

	let mut buf = Zeroizing::new([0u8; P256_SECRET_LEN]);
	hk.expand(&[], &mut *buf)
		.map_err(|_| QuorumKeyError::HkdfExpansionFailed)?;

	Ok(buf)
}

/// Helper function to generate a `N` length byte buffer.
#[must_use]
pub fn bytes_os_rng<const N: usize>() -> [u8; N] {
	let mut key = [0u8; N];
	OsRng.fill_bytes(&mut key);

	key
}

/// A secret to create a [`QuorumKey`]
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub enum VersionedSecret {
	V0([u8; 32]),
	V1([u8; 97]),
}

impl VersionedSecret {
	/// Parse a secret from raw bytes.
	fn from_bytes(bytes: &[u8]) -> Result<Self, QuorumKeyError> {
		if let Ok(array) = TryInto::<[u8; 97]>::try_into(bytes) {
			// Validations from spec `PARSE_SECRET`
			if array[0] == SECRET_V1 {
				let this = Self::V1(array);

				// Validate hpke_secret and sign_secret are valid P256 scalars
				P256EncryptPair::from_bytes(&*this.hpke_secret()?)?;
				P256SignPair::from_bytes(&*this.sign_secret()?)?;

				return Ok(this);
			}
		} else if let Ok(array) = TryInto::<[u8; 32]>::try_into(bytes) {
			return Ok(Self::V0(array));
		}

		Err(QuorumKeyError::FailedToReadSecret)
	}

	/// Get the secret bytes
	pub fn as_bytes(&self) -> &[u8] {
		match self {
			Self::V0(ref b) => b,
			Self::V1(ref b) => b,
		}
	}

	/// Get the HPKE (encryption) secret bytes.
	pub fn hpke_secret(&self) -> Result<Zeroizing<[u8; 32]>, QuorumKeyError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, P256_ENCRYPT_DERIVE_PATH),
			Self::V1(bytes) => Ok(Zeroizing::new(
				bytes[1..33].try_into().expect("exactly 32 bytes. qed."),
			)),
		}
	}

	/// Get the signing secret bytes.
	pub fn sign_secret(&self) -> Result<Zeroizing<[u8; 32]>, QuorumKeyError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, P256_SIGN_DERIVE_PATH),
			Self::V1(bytes) => Ok(Zeroizing::new(
				bytes[33..65].try_into().expect("exactly 32 bytes. qed."),
			)),
		}
	}

	/// Get the AES-GCM-256 symmetric encryption secret bytes.
	pub fn aes_gcm_256_secret(
		&self,
	) -> Result<Zeroizing<[u8; 32]>, QuorumKeyError> {
		match &self {
			Self::V0(seed) => derive_secret(seed, AES_GCM_256_PATH),
			Self::V1(bytes) => Ok(Zeroizing::new(
				bytes[65..].try_into().expect("exactly 32 bytes. qed."),
			)),
		}
	}
}

/// P256 private key pair for signing and encryption. Internally this uses a
/// separate secret for signing and encryption.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct QuorumKey {
	p256_encrypt_private: P256EncryptPair,
	sign_private: P256SignPair,
	aes_gcm_256_secret: AesGcm256Secret,
	versioned_secret: VersionedSecret,
}

impl QuorumKey {
	/// Generate a new private key using the OS randomness source.
	pub fn generate() -> Result<Self, QuorumKeyError> {
		let mut bytes = bytes_os_rng::<97>();
		bytes[0] = SECRET_V1;
		let versioned_secret = VersionedSecret::from_bytes(&bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&*versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&*versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				*versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Generate a key set with a V0 secret.
	pub fn generate_v0() -> Result<Self, QuorumKeyError> {
		// V0 secrets are 32 bytes
		let bytes = bytes_os_rng::<32>();
		let versioned_secret = VersionedSecret::from_bytes(&bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&*versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&*versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				*versioned_secret.aes_gcm_256_secret()?,
			)?,
			versioned_secret,
		})
	}

	/// Encrypt the given `msg` with the symmetric encryption secret.
	pub fn aes_gcm_256_encrypt(
		&self,
		msg: &[u8],
	) -> Result<Vec<u8>, QuorumKeyError> {
		self.aes_gcm_256_secret.encrypt(msg)
	}

	/// Decrypt a message with the symmetric encryption secret.
	pub fn aes_gcm_256_decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, QuorumKeyError> {
		self.aes_gcm_256_secret.decrypt(serialized_envelope)
	}

	/// Decrypt a message encoded to this pair's public key.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Vec<u8>, QuorumKeyError> {
		self.p256_encrypt_private.decrypt(serialized_envelope)
	}

	/// Sign the message and return the raw signature.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, QuorumKeyError> {
		self.sign_private.sign(message)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> QuorumKeyPublic {
		QuorumKeyPublic {
			encrypt_public: self.p256_encrypt_private.public_key(),
			sign_public: self.sign_private.public_key(),
		}
	}

	/// Create `Self` from the raw bytes of the versioned secret.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, QuorumKeyError> {
		let versioned_secret = VersionedSecret::from_bytes(bytes)?;

		Ok(Self {
			p256_encrypt_private: P256EncryptPair::from_bytes(
				&*versioned_secret.hpke_secret()?,
			)?,
			sign_private: P256SignPair::from_bytes(
				&*versioned_secret.sign_secret()?,
			)?,
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(
				*versioned_secret.aes_gcm_256_secret()?,
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
	) -> Result<(), QuorumKeyError> {
		let hex_string = qos_hex::encode(self.versioned_secret.as_bytes());
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			QuorumKeyError::IOError(format!(
				"failed to write master secret to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the raw, hex encoded master from a file.
	pub fn from_hex_file<P: AsRef<Path>>(
		path: P,
	) -> Result<Self, QuorumKeyError> {
		let hex = std::fs::read_to_string(&path).map_err(|e| {
			QuorumKeyError::IOError(format!(
				"failed to read master seed from {}: {e}",
				path.as_ref().display()
			))
		})?;
		let hex = hex.trim();

		let versioned_secret =
			qos_hex::decode(hex).map_err(QuorumKeyError::from)?;
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
	pub fn quorum_key_id(&self) -> Result<QuorumKeyId, QuorumKeyError> {
		let key_id =
			aes_gcm_256_key_id(&*self.versioned_secret.aes_gcm_256_secret()?)?;
		QuorumKeyId::from_parts(
			&self.p256_encrypt_private.public_key().to_bytes(),
			&self.sign_private.public_key().to_bytes(),
			&key_id,
		)
	}
}

/// P256 public keys for signing and encryption. Internally this uses
/// separate public keys for signing and encryption.
///
/// Note: as of V1, this is not a complete identifier for a Quorum Key Set as
/// it does not identify the associated AES GCM 256 secret. Use `[QuorumKeyId]`
/// and/or the associated fingerprint to identify a Quorum Key Set.
#[derive(Clone, PartialEq, Eq)]
pub struct QuorumKeyPublic {
	encrypt_public: P256EncryptPublic,
	sign_public: P256SignPublic,
}

impl QuorumKeyPublic {
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, QuorumKeyError> {
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
	) -> Result<(), QuorumKeyError> {
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
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, QuorumKeyError> {
		if bytes.len() > PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(QuorumKeyError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUB_KEY_LEN_UNCOMPRESSED as usize * 2 {
			return Err(QuorumKeyError::EncodedPublicKeyTooShort);
		}

		let (encrypt_bytes, sign_bytes) =
			bytes.split_at(PUB_KEY_LEN_UNCOMPRESSED as usize);

		Ok(Self {
			encrypt_public: P256EncryptPublic::from_bytes(encrypt_bytes)
				.map_err(|_| QuorumKeyError::FailedToReadPublicKey)?,
			sign_public: P256SignPublic::from_bytes(sign_bytes)
				.map_err(|_| QuorumKeyError::FailedToReadPublicKey)?,
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
	) -> Result<(), QuorumKeyError> {
		let hex_string = format!("{}\n", qos_hex::encode(&self.to_bytes()));
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			QuorumKeyError::IOError(format!(
				"failed to write public key bytes to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the hex encoded public keys from a file.
	pub fn from_hex_file<P: AsRef<Path>>(
		path: P,
	) -> Result<Self, QuorumKeyError> {
		let hex = std::fs::read_to_string(&path).map_err(|e| {
			QuorumKeyError::IOError(format!(
				"failed to read public key bytes from {}: {e}",
				path.as_ref().display()
			))
		})?;
		let hex = hex.trim();

		let public_keys_bytes =
			qos_hex::decode(hex).map_err(QuorumKeyError::from)?;

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
pub fn aes_gcm_256_key_id(secret: &[u8]) -> Result<[u8; 32], QuorumKeyError> {
	let prk = Hkdf::<sha2::Sha256>::new(None, secret);

	let mut buf = [0u8; 32];
	prk.expand(AES_GCM_256_KEY_ID_INFO, &mut buf)
		.map_err(|_| QuorumKeyError::HkdfExpansionFailed)?;

	Ok(buf)
}

/// Identifier for a quorum key set containing public keys and a derived key ID.
pub struct QuorumKeyId {
	hpke_public: [u8; 65],
	sign_public: [u8; 65],
	aes_gcm_256_key_id: [u8; 32],
}

impl QuorumKeyId {
	/// Create a quorum key from requisite key identifiers.
	///
	/// Validates that `hpke_public` and `sign_public` are valid SEC1
	/// uncompressed P256 points.
	pub fn from_parts(
		hpke_public: &[u8],
		sign_public: &[u8],
		aes_gcm_256_key_id: &[u8],
	) -> Result<Self, QuorumKeyError> {
		// Validate that the public keys are valid SEC1 uncompressed points
		P256EncryptPublic::from_bytes(hpke_public)?;
		P256SignPublic::from_bytes(sign_public)?;

		let hpke_public = hpke_public
			.try_into()
			.map_err(|_| QuorumKeyError::FailedToReadPublicKey)?;
		let sign_public = sign_public
			.try_into()
			.map_err(|_| QuorumKeyError::FailedToReadPublicKey)?;
		let aes_gcm_256_key_id = aes_gcm_256_key_id
			.try_into()
			.map_err(|_| QuorumKeyError::FailedToReadPublicKey)?;

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

	/// Parse a QuorumKeyId from bytes.
	///
	/// Expects 163 bytes: `version || hpke_public || sign_public || aes_gcm_256_key_id`
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, QuorumKeyError> {
		if bytes.len() != 163 {
			return Err(QuorumKeyError::FailedToReadPublicKey);
		}
		if bytes[0] != QUORUM_KEY_ID_V1 {
			return Err(QuorumKeyError::FailedToReadPublicKey);
		}

		Self::from_parts(&bytes[1..66], &bytes[66..131], &bytes[131..163])
	}
}

#[cfg(test)]
mod test {
	use qos_test_primitives::PathWrapper;

	use super::*;

	#[test]
	fn signatures_are_deterministic() {
		let message = b"a message to authenticate";

		let pair = QuorumKey::generate().unwrap();
		(0..100)
			.map(|_| pair.sign(message).unwrap())
			.collect::<Vec<_>>()
			.windows(2)
			.for_each(|slice| assert_eq!(slice[0], slice[1]));
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = QuorumKey::generate().unwrap();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn v0_sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = QuorumKey::generate_v0().unwrap();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = QuorumKey::generate().unwrap();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = QuorumKey::generate().unwrap().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			QuorumKeyError::FailedSignatureVerification
		);
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = QuorumKey::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn v0_basic_encrypt_decrypt_works() {
		let alice_pair = QuorumKey::generate_v0().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = QuorumKey::generate().unwrap();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext).unwrap();

		let bob_pair = QuorumKey::generate().unwrap();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			QuorumKeyError::AesGcm256DecryptError
		);
	}

	#[test]
	fn public_key_bytes_roundtrip() {
		let alice_pair = QuorumKey::generate().unwrap();
		let alice_public = alice_pair.public_key();
		let alice_public_bytes = alice_public.to_bytes();

		assert_eq!(
			alice_public_bytes.len(),
			PUB_KEY_LEN_UNCOMPRESSED as usize * 2
		);

		let alice_public2 =
			QuorumKeyPublic::from_bytes(&alice_public_bytes).unwrap();

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
		let alice_pair = QuorumKey::generate().unwrap();
		let alice_public = alice_pair.public_key();

		alice_public.to_hex_file(&*path).unwrap();

		let alice_public2 = QuorumKeyPublic::from_hex_file(&*path).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();
		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair.sign(message).unwrap();
		assert!(alice_public2.verify(message, &signature).is_ok());
	}

	// Explicitly use v0 versioned secret
	#[test]
	fn master_seed_bytes_roundtrip() {
		let alice_pair = QuorumKey::generate_v0().unwrap();
		let public_key = alice_pair.public_key();
		let master_seed = alice_pair.as_bytes();

		let alice_pair2 = QuorumKey::from_bytes(master_seed).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = public_key.encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());
	}

	#[test]
	fn versioned_secrets_bytes_roundtrip() {
		let alice_pair = QuorumKey::generate().unwrap();
		let public_key = alice_pair.public_key();
		let secret = alice_pair.as_bytes();

		let alice_pair2 = QuorumKey::from_bytes(secret).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope = public_key.encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());
	}

	// Explicitly use v0 versioned secret
	#[test]
	fn master_seed_to_file_round_trip() {
		let path: PathWrapper =
			"/tmp/master_seed_to_file_round_trip.secret".into();

		let alice_pair = QuorumKey::generate_v0().unwrap();
		alice_pair.to_hex_file(&*path).unwrap();

		let alice_pair2 = QuorumKey::from_hex_file(&*path).unwrap();

		let plaintext = b"rust test message";
		let serialized_envelope =
			alice_pair.public_key().encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(decrypted, plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(alice_pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn versioned_secret_to_file_round_trip() {
		let path: PathWrapper =
			"/tmp/versioned_secret_to_file_round_trip.secret".into();

		let alice_pair = QuorumKey::generate().unwrap();
		alice_pair.to_hex_file(&*path).unwrap();

		let alice_pair2 = QuorumKey::from_hex_file(&*path).unwrap();

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

			let key = QuorumKey::generate().unwrap();

			let envelope = key.aes_gcm_256_encrypt(plaintext).unwrap();
			let result = key.aes_gcm_256_decrypt(&envelope).unwrap();

			assert_eq!(result, plaintext);
		}

		#[test]
		fn different_key_cannot_decrypt() {
			let plaintext = b"rust test message";
			let key = QuorumKey::generate().unwrap();
			let other_key = QuorumKey::generate().unwrap();

			let serialized_envelope =
				key.aes_gcm_256_encrypt(plaintext).unwrap();

			let err = other_key
				.aes_gcm_256_decrypt(&serialized_envelope)
				.unwrap_err();
			assert_eq!(err, QuorumKeyError::AesGcm256DecryptError,);
		}
	}

	// Known answer test. Values can be used as test vectors for
	// other implementations.
	#[test]
	fn quorum_key_id_works() {
		let v0_secret = qos_hex::decode(
			"c56d1a681fca7fc6402fe325a8ca5b65f743907e16bc468795f44bca4020e67b",
		)
		.unwrap();
		let v1_secret = qos_hex::decode(
				"0106422fe2b549236d0f829686984addea6859d28736afcbea74ae684e1cb1e6bd4dcec5f81816ce98e58d0d009e7fc73b6c7d13e8da59b116d52c34c667ffd9a9feb93b1b850ec84bc28a93c0c22868b885bea24aae8a8581d78d7d013c63f479",
			)
			.unwrap();

		let v0_key = QuorumKey::from_bytes(&v0_secret).unwrap();
		let v1_key = QuorumKey::from_bytes(&v1_secret).unwrap();

		let v0_id = v0_key.quorum_key_id().unwrap();
		let v1_id = v1_key.quorum_key_id().unwrap();

		let v0_fingerprint = v0_id.fingerprint();
		let v1_fingerprint = v1_id.fingerprint();

		let v0_public = v0_key.public_key();
		let v1_public = v1_key.public_key();

		let expected_v0_id = qos_hex::decode(
				"010481d34ce6eb734228ed8302be0852157a1602735b904541fd6d2c0f4294ee23dce451396110719966c7f987bfb814f7a0e4e1e38794c3c697d13e613e1ad0a76b0442f3d7b73e08a23a4568c85c59de1216e1c279cfbcf02adcf370f59b8fea602fd322ca4cbae20fee70bd9a8e5c579e546a8c99644bce7174be8a3ade148f361e2ac6e762303782bc083d25fb1d029f39a2f76e87115b067a2c20130ac480ab6a",
			)
			.unwrap();
		let expected_v1_id = qos_hex::decode(
				"01040d99146818b0bd971a4ad6b423275feecab4d001da35e4fe03fc83e5fe2cd35e63b382479fae11d3fbbc04f9febd33e737757a77da5119c9c8c4b588dab1cf880411950611dfba917695171766fa7a1ab8abe0678fe4cc2fa80c32d343c9d19b71b68f75b036c70e222c19fe2014d8c486836e4a769f310832c8fcfc6a8e3d4bf7c44f0ab0be9f51b0ef9bfaa0c25bebe9b5dd1c09163bd93ed820559c46aca5ec",
			)
			.unwrap();
		let expected_v0_fingerprint = qos_hex::decode(
			"3c22450be1f8f1da1ffaa82b4a41357b35add734a1b85cf1cb6b0a4f429a5d80",
		)
		.unwrap();
		let expected_v1_fingerprint = qos_hex::decode(
			"9f089ad98807f4d2f49601c3462c33999fb2a82f697822aa2d401414245945d5",
		)
		.unwrap();

		// Assert key ids match expected
		assert_eq!(expected_v0_id, v0_id.to_bytes());
		assert_eq!(expected_v1_id, v1_id.to_bytes());

		// Assert fingerprints match expected
		assert_eq!(expected_v0_fingerprint, v0_fingerprint);
		assert_eq!(expected_v1_fingerprint, v1_fingerprint);

		// Assert fingerprints are sha_256 of key ids
		assert_eq!(v0_fingerprint, qos_crypto::sha_256(&v0_id.to_bytes()));
		assert_eq!(v1_fingerprint, qos_crypto::sha_256(&v1_id.to_bytes()));

		// Assert public key bytes (130) are equal to bytes[1..131] of key id
		assert_eq!(&v0_public.to_bytes()[..], &v0_id.to_bytes()[1..131]);
		assert_eq!(&v1_public.to_bytes()[..], &v1_id.to_bytes()[1..131]);
	}

	mod versioned_secret_validation {
		use super::*;

		#[test]
		fn rejects_wrong_version_byte_for_97_bytes() {
			let mut bytes = [0u8; 97];
			// Set version to 0x02 instead of 0x01
			bytes[0] = 0x02;
			// Fill with valid-ish data (won't matter since version check fails)
			bytes[1..33].copy_from_slice(&[1u8; 32]);
			bytes[33..65].copy_from_slice(&[2u8; 32]);
			bytes[65..97].copy_from_slice(&[3u8; 32]);

			assert!(matches!(
				VersionedSecret::from_bytes(&bytes),
				Err(QuorumKeyError::FailedToReadSecret)
			));
		}

		#[test]
		fn rejects_invalid_p256_scalar_all_zeros() {
			let mut bytes = [0u8; 97];
			bytes[0] = SECRET_V1;
			// hpke_secret is all zeros - invalid P256 scalar
			// sign_secret and aes_gcm_256_secret don't matter

			assert!(matches!(
				VersionedSecret::from_bytes(&bytes),
				Err(QuorumKeyError::FailedToReadSecret)
			));
		}

		#[test]
		fn rejects_invalid_lengths() {
			// Too short for V0
			assert!(matches!(
				VersionedSecret::from_bytes(&[0u8; 31]),
				Err(QuorumKeyError::FailedToReadSecret)
			));

			// Between V0 and V1
			assert!(matches!(
				VersionedSecret::from_bytes(&[0u8; 33]),
				Err(QuorumKeyError::FailedToReadSecret)
			));
			assert!(matches!(
				VersionedSecret::from_bytes(&[0u8; 96]),
				Err(QuorumKeyError::FailedToReadSecret)
			));

			// Too long for V1
			assert!(matches!(
				VersionedSecret::from_bytes(&[0u8; 98]),
				Err(QuorumKeyError::FailedToReadSecret)
			));
		}
	}

	mod quorum_key_id_parsing {
		use super::*;

		#[test]
		fn from_bytes_roundtrip() {
			let key = QuorumKey::generate().unwrap();
			let id = key.quorum_key_id().unwrap();
			let bytes = id.to_bytes();

			let parsed = QuorumKeyId::from_bytes(&bytes).unwrap();

			assert_eq!(parsed.to_bytes(), bytes);
			assert_eq!(parsed.fingerprint(), id.fingerprint());
		}

		#[test]
		fn rejects_wrong_length() {
			assert!(QuorumKeyId::from_bytes(&[0u8; 162]).is_err());
			assert!(QuorumKeyId::from_bytes(&[0u8; 164]).is_err());
			assert!(QuorumKeyId::from_bytes(&[0u8; 130]).is_err());
		}

		#[test]
		fn rejects_wrong_version_byte() {
			let key = QuorumKey::generate().unwrap();
			let id = key.quorum_key_id().unwrap();
			let mut bytes = id.to_bytes();

			// Change version byte
			bytes[0] = 0x02;

			assert!(QuorumKeyId::from_bytes(&bytes).is_err());
		}

		#[test]
		fn rejects_invalid_public_keys() {
			let mut bytes = [0u8; 163];
			bytes[0] = QUORUM_KEY_ID_V1;
			// Rest is zeros - invalid SEC1 points

			assert!(QuorumKeyId::from_bytes(&bytes).is_err());
		}
	}
}
