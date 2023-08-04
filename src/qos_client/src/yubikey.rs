//! Yubikey interfaces

use std::{
	fs::File,
	io::{BufRead, BufReader},
	path::Path,
};

use borsh::BorshDeserialize;
use p256::{
	ecdsa::{signature::Verifier, Signature, VerifyingKey},
	elliptic_curve::sec1::ToEncodedPoint,
	SecretKey,
};
use qos_p256::{encrypt::Envelope, P256Error, P256Pair};
use rand_core::{OsRng, RngCore};
use x509::RelativeDistinguishedName;
use yubikey::{
	certificate::{Certificate, PublicKeyInfo},
	piv::{self, AlgorithmId, SlotId},
	MgmKey, PinPolicy, TouchPolicy, YubiKey,
};
use zeroize::Zeroizing;

// "Key Agree" refers to ECDH because two parties agree on a shared key.
// https://docs.yubico.com/yesdk/users-manual/application-piv/key-agreement.html
// https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/auth-key-agree.html
/// The slot we expect the ECDH key on.
pub const KEY_AGREEMENT_SLOT: SlotId = SlotId::KeyManagement;
/// The slot we always expect the signing key on.
pub const SIGNING_SLOT: SlotId = SlotId::Signature;
/// Factory default pin for yubikeys.
pub const DEFAULT_PIN: &[u8] = b"123456";
/// Yubikey pin prompt
pub const ENTER_PIN_PROMPT: &str = "Enter your pin: ";
/// Yubikey tap message
pub const TAP_MSG: &str = "Tap your YubiKey";
const ALGO: AlgorithmId = AlgorithmId::EccP256;


/// Errors for yubikey interaction
#[derive(Debug, PartialEq, Eq)]
pub enum YubiKeyError {
	/// Failed to generate a key.
	FailedToGenerateKey,
	/// Failed to authorize with the management key.
	FailedToAuthWithMGM,
	/// Failed to verify a pin.
	FailedToVerifyPin(yubikey::Error),
	/// Failed to generate a self signed certificate.
	FailedToGenerateSelfSignedCert,
	/// Will not overwrite a slot that already has a certificate.
	WillNotOverwriteSlot,
	/// Cannot find a key on the signing slot.
	CannotFindSigningKey,
	/// Cannot find a key on the key management slot.
	CannotFindKeyAgree,
	/// Found a key that was not P256 when one was expected.
	FoundNonP256Key,
	/// Error from qos p256.
	P256(qos_p256::P256Error),
	/// An error trying to read a pin from the terminal
	#[cfg(feature = "smartcard")]
	PinEntryError,
	/// Could not deserialize a public key.
	CouldNotDeserializePublic,
	/// Signing with the yubikey failed
	SigningFailed(yubikey::Error),
	/// The signature generate by the yubikey could not be verified.
	FailedToVerifyYubiKeySignature,
	/// The key agreement (ECDH) from the yubikey failed.
	KeyAgreementFailed,
	/// Connecting to the yubikey failed. Make sure only 1 key is plugged in
	/// and try re-plugging in the device.
	Connection(yubikey::Error),
	/// Failed to deserialize the encryption envelope.
	EnvelopeDeserialize,
	/// Faild to load key data onto yubikey.
	FailedToLoadKey,
	/// The secret is invalid.
	InvalidSecret,
	/// The pin could not be changed.
	FailedToChangePin,
}

impl From<P256Error> for YubiKeyError {
	fn from(err: P256Error) -> Self {
		YubiKeyError::P256(err)
	}
}

/// Use a P256 key pair or Yubikey for signing operations.
pub enum PairOrYubi {
	#[cfg(feature = "smartcard")]
	/// Yubikey
	Yubi((yubikey::YubiKey, Vec<u8>)),
	/// P256 key pair
	Pair(P256Pair),
}

impl PairOrYubi {
	/// Create a P256 key pair or yubikey from the given inputs
	pub fn from_inputs(
		yubikey_flag: bool,
		secret_path: Option<String>,
		maybe_pin_path: Option<String>,
	) -> Result<Self, YubiKeyError> {
		let result = match (yubikey_flag, secret_path) {
			(true, None) => {
				#[cfg(feature = "smartcard")]
				{
					let yubi = crate::yubikey::open_single()?;

					let pin = if let Some(pin_path) = maybe_pin_path {
						pin_from_path(pin_path)
					} else {
						rpassword::prompt_password(ENTER_PIN_PROMPT)
							.map_err(|_| YubiKeyError::PinEntryError)?
							.as_bytes()
							.to_vec()
					};

					PairOrYubi::Yubi((yubi, pin))
				}
				#[cfg(not(feature = "smartcard"))]
				{
					panic!("{TAP_MSG}");
				}
			}
			(false, Some(path)) => {
				let pair = P256Pair::from_hex_file(path)?;
				PairOrYubi::Pair(pair)
			}
			(false, None) => panic!("Need either yubikey flag or secret path"),
			(true, Some(_)) => {
				panic!("Cannot have both yubikey flag and secret path")
			}
		};

		Ok(result)
	}

	/// Sign the payload
	pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, YubiKeyError> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, ref pin)) => {
				println!("{TAP_MSG}");
				crate::yubikey::sign_data(yubi, data, pin).map_err(Into::into)
			}
			Self::Pair(ref pair) => pair.sign(data).map_err(Into::into),
		}
	}

	/// Decrypt the payload
	pub fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, YubiKeyError> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, ref pin)) => {
				println!("{TAP_MSG}");
				let shared_secret =
					crate::yubikey::shared_secret(yubi, payload, pin)?;
				let encrypt_pub = crate::yubikey::key_agree_public_key(yubi)?;
				let public = qos_p256::encrypt::P256EncryptPublic::from_bytes(
					&encrypt_pub,
				)?;

				public
					.decrypt_from_shared_secret(payload, &shared_secret)
					.map_err(Into::into)
			}
			Self::Pair(ref pair) => pair.decrypt(payload).map_err(Into::into),
		}
	}

	/// Get the public key in bytes
	pub fn public_key_bytes(&mut self) -> Result<Vec<u8>, YubiKeyError> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, _)) => {
				crate::yubikey::pair_public_key(yubi).map_err(Into::into)
			}
			Self::Pair(ref pair) => Ok(pair.public_key().to_bytes()),
		}
	}
}


pub(crate) fn pin_from_path<P: AsRef<Path>>(path: P) -> Vec<u8> {
	let file = File::open(path).expect("Failed to open current pin path");
	BufReader::new(file)
		.lines()
		.next()
		.expect("First line missing from current pin file")
		.expect("Error reading first line")
		.as_bytes()
		.to_vec()
}

/// Generate a signed certificate with a p256 key for the given `slot`.
///
/// Returns the public key as an uncompressed encoded point.
pub fn generate_signed_certificate(
	yubikey: &mut YubiKey,
	slot: SlotId,
	pin: &[u8],
	mgm_key: MgmKey,
	touch_policy: TouchPolicy,
) -> Result<Box<[u8]>, YubiKeyError> {
	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	yubikey
		.authenticate(mgm_key)
		.map_err(|_| YubiKeyError::FailedToAuthWithMGM)?;

	// Check that there is no key already in the slot
	if Certificate::read(yubikey, slot).is_ok() {
		return Err(YubiKeyError::WillNotOverwriteSlot);
	}

	// Generate a key in the slot
	let public_key_info =
		piv::generate(yubikey, slot, ALGO, PinPolicy::Always, touch_policy)
			.map_err(|_| YubiKeyError::FailedToGenerateKey)?;
	let encoded_point = extract_encoded_point(&public_key_info)?;

	// Create a random serial number
	let mut serial = [0u8; 20];
	OsRng.fill_bytes(&mut serial);

	// Don't add any extensions
	let extensions: &[x509::Extension<'_, &[u64]>] = &[];

	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	Certificate::generate_self_signed(
		yubikey,
		slot,
		serial,
		None, // not_after is none so this never expires
		&[RelativeDistinguishedName::organization("Turnkey")],
		public_key_info,
		extensions,
	)
	.map_err(|_| YubiKeyError::FailedToGenerateSelfSignedCert)?;

	Ok(encoded_point.to_bytes())
}

/// Import the given `key_data` onto the `yubikey` and create a signed
/// certificate for the key.
pub fn import_key_and_generate_signed_certificate(
	yubikey: &mut YubiKey,
	key_data: &[u8],
	slot: SlotId,
	pin: &[u8],
	mgm_key: MgmKey,
	touch_policy: TouchPolicy,
) -> Result<(), YubiKeyError> {
	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	yubikey
		.authenticate(mgm_key)
		.map_err(|_| YubiKeyError::FailedToAuthWithMGM)?;

	// Check that there is no key already in the slot
	if Certificate::read(yubikey, slot).is_ok() {
		return Err(YubiKeyError::WillNotOverwriteSlot);
	}

	let public_key_info = {
		let encoded_point = SecretKey::from_be_bytes(key_data)
			.map_err(|_| YubiKeyError::InvalidSecret)?
			.public_key()
			.to_encoded_point(false);
		PublicKeyInfo::EcP256(encoded_point)
	};

	// Import a key in the slot
	piv::import_ecc_key(
		yubikey,
		slot,
		ALGO,
		key_data,
		touch_policy,
		PinPolicy::Always,
	)
	.map_err(|_| YubiKeyError::FailedToLoadKey)?;

	// Create a random serial number
	let mut serial = [0u8; 20];
	OsRng.fill_bytes(&mut serial);

	// Don't add any extensions
	let extensions: &[x509::Extension<'_, &[u64]>] = &[];

	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	Certificate::generate_self_signed(
		yubikey,
		slot,
		serial,
		None, // not_after is none so this never expires
		&[RelativeDistinguishedName::organization("Turnkey")],
		public_key_info,
		extensions,
	)
	.map_err(|_| YubiKeyError::FailedToGenerateSelfSignedCert)?;

	Ok(())
}

/// Sign data with the yubikey and return the signature as a raw bytes.
pub fn sign_data(
	yubikey: &mut YubiKey,
	data: &[u8],
	pin: &[u8],
) -> Result<Vec<u8>, YubiKeyError> {
	// Get the public key for signing
	let signing_slot_cert = Certificate::read(yubikey, SIGNING_SLOT)
		.map_err(|_| YubiKeyError::CannotFindSigningKey)?;
	let public_key_info = signing_slot_cert.subject_pki();
	let encoded_point = extract_encoded_point(public_key_info)?;
	let verifying_key = VerifyingKey::from_sec1_bytes(encoded_point.as_bytes())
		.map_err(|_| YubiKeyError::FoundNonP256Key)?;

	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;

	let der_sig = piv::sign_data(
		yubikey,
		// Note: yubikey assumes the data is pre-hashed, but p256 verification
		// hashes for us
		&qos_crypto::sha_256(data),
		ALGO,
		SIGNING_SLOT,
	)
	.map_err(YubiKeyError::SigningFailed)?;

	let signature =
		Signature::from_der(&der_sig).expect("Yubikey returns der signature");

	verifying_key
		.verify(data, &signature)
		.map_err(|_| YubiKeyError::FailedToVerifyYubiKeySignature)?;

	Ok(signature.to_vec())
}

/// Generate a ECDH shared secret against the key management slot and the
/// `sender_public_key`.
///
/// `sender_public_key` is an uncompressed encoded point of the public key used
/// by the sender to create the shared secret.
pub fn key_agreement(
	yubikey: &mut YubiKey,
	sender_public_key: &[u8],
	pin: &[u8],
) -> Result<Zeroizing<Vec<u8>>, YubiKeyError> {
	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;

	piv::decrypt_data(yubikey, sender_public_key, ALGO, KEY_AGREEMENT_SLOT)
		.map_err(|_| YubiKeyError::KeyAgreementFailed)
}

/// Open the single connected yubikey.
pub fn open_single() -> Result<YubiKey, YubiKeyError> {
	YubiKey::open().map_err(YubiKeyError::Connection)
}

/// Get the public key from the yubikey that corresponds to
/// `P256Public::to_bytes`. This is the key agree public key concatenated with
/// the signature public key. Encodes as `encrypt_public||sign_public`.
pub fn pair_public_key(yubikey: &mut YubiKey) -> Result<Vec<u8>, YubiKeyError> {
	let signing_slot_cert = Certificate::read(yubikey, SIGNING_SLOT)
		.map_err(|_| YubiKeyError::CannotFindSigningKey)?;
	let signing_public_key_info = signing_slot_cert.subject_pki();
	let signing_encoded_point = extract_encoded_point(signing_public_key_info)?;

	let pair_public_key: Vec<_> = key_agree_public_key(yubikey)?
		.iter()
		.chain(signing_encoded_point.to_bytes().iter())
		.copied()
		.collect();

	Ok(pair_public_key)
}

/// Get the public key on the key agree slot.
pub fn key_agree_public_key(
	yubikey: &mut YubiKey,
) -> Result<Vec<u8>, YubiKeyError> {
	let key_agree_slot_cert = Certificate::read(yubikey, KEY_AGREEMENT_SLOT)
		.map_err(|_| YubiKeyError::CannotFindKeyAgree)?;
	let key_agree_key_info = key_agree_slot_cert.subject_pki();
	let key_agree_key_encoded_point =
		extract_encoded_point(key_agree_key_info)?;

	Ok(key_agree_key_encoded_point.to_bytes().to_vec())
}

/// Get the shared secret with a connected yubikey and the public key in the
/// given `serialized_envelope`.
///
/// Returns `(shared_secret, public_key_bytes)`.
pub fn shared_secret(
	yubikey: &mut YubiKey,
	serialized_envelope: &[u8],
	pin: &[u8],
) -> Result<Zeroizing<Vec<u8>>, YubiKeyError> {
	// get the sender eph key from the encryption envelope
	let sender_pub_bytes = {
		let decoded = Envelope::try_from_slice(serialized_envelope)
			.map_err(|_| YubiKeyError::EnvelopeDeserialize)?;
		decoded.ephemeral_sender_public
	};

	key_agreement(yubikey, &sender_pub_bytes, pin)
}

/// Change the PIV authorization PIN on the yubikey.
pub fn yubikey_change_pin(
	current_pin: &[u8],
	new_pin: &[u8],
) -> Result<(), YubiKeyError> {
	let mut yubikey = open_single()?;
	yubikey
		.change_pin(current_pin, new_pin)
		.map_err(|_| YubiKeyError::FailedToChangePin)?;
	Ok(())
}

/// Reset the PIV app on the attached yubikey.
///
/// **WARNING:** This will delete all private keys on the PIV app.
pub fn yubikey_piv_reset() -> Result<(), YubiKeyError> {
	let mut yubikey = open_single()?;
	// Pins need to be blocked before device can be reset
	for _ in 0..3 {
		let _ = yubikey.authenticate(yubikey::MgmKey::generate());
		let _ = yubikey.verify_pin(b"000000");
	}
	let _ = yubikey.block_puk();
	let _ = yubikey.reset_device();
	Ok(())
}

fn extract_encoded_point(
	public_key_info: &PublicKeyInfo,
) -> Result<p256::EncodedPoint, YubiKeyError> {
	match public_key_info {
		PublicKeyInfo::EcP256(encoded_point) => Ok(*encoded_point),
		_ => Err(YubiKeyError::FoundNonP256Key),
	}
}
