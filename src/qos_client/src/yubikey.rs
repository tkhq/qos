//! Yubikey interfaces

use borsh::BorshDeserialize;
use p256::{
	ecdsa::{signature::Verifier, Signature, VerifyingKey},
	pkcs8::SubjectPublicKeyInfo,
	SecretKey,
};
use qos_p256::encrypt::Envelope;
use rand_core::{OsRng, TryRngCore};
use std::{str::FromStr, time::Duration};
use x509_cert::{
	name::RdnSequence, serial_number::SerialNumber, time::Validity,
};
use yubikey::{
	certificate::Certificate,
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
const ALGO: AlgorithmId = AlgorithmId::EccP256;
/// Equivalent to about 10 years
/// Chosen arbitrarily as a long certificate validity
const CERTIFICATE_VALIDITY_SECS: u32 = 10 * 60 * 60 * 24 * 365;
/// Generic information for newly generated local certificates
const CERTIFICATE_DISTINGUISHED_NAME: &str = "CN=QuorumOS";

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
	/// See [`der::Error`] for inner string contents.
	DerError(String),
}

impl From<der::Error> for YubiKeyError {
	fn from(from: der::Error) -> Self {
		// add a debug-print of the inner error
		Self::DerError(format!("{from:?}"))
	}
}

/// Generate a signed certificate with a p256 key for the given `slot`.
///
/// Returns the public key as an uncompressed encoded point.
///
/// # Panics
/// Panics if the `OsRng` is unable to provide data, which shouldn't happen in normal operation.
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
	let encoded_point =
		extract_encoded_point(public_key_info.subject_public_key.as_bytes())?;

	// Create a random serial number compliant with RFC5280
	let serial = generate_random_rfc5280_serial();

	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	Certificate::generate_self_signed::<_, p256::NistP256>(
		yubikey,
		slot,
		SerialNumber::new(&serial)?,
		Validity::from_now(Duration::from_secs(
			CERTIFICATE_VALIDITY_SECS.into(),
		))?,
		RdnSequence::from_str(CERTIFICATE_DISTINGUISHED_NAME)?,
		public_key_info,
		|_| Ok(()),
	)
	.map_err(|_| YubiKeyError::FailedToGenerateSelfSignedCert)?;

	Ok(encoded_point.to_bytes())
}

/// Import the given `key_data` onto the `yubikey` and create a signed
/// certificate for the key.
///
/// # Panics
/// Panics if the `OsRng` is unable to provide data, which shouldn't happen in normal operation.
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

	let public_key_info = SecretKey::from_slice(key_data)
		.ok()
		.and_then(|sk| SubjectPublicKeyInfo::from_key(sk.public_key()).ok())
		.ok_or(YubiKeyError::InvalidSecret)?;

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

	// Create a random serial number compliant with RFC5280
	let serial = generate_random_rfc5280_serial();

	yubikey.verify_pin(pin).map_err(YubiKeyError::FailedToVerifyPin)?;
	Certificate::generate_self_signed::<_, p256::NistP256>(
		yubikey,
		slot,
		SerialNumber::new(&serial)?,
		Validity::from_now(Duration::from_secs(
			CERTIFICATE_VALIDITY_SECS.into(),
		))?,
		RdnSequence::from_str(CERTIFICATE_DISTINGUISHED_NAME)?,
		public_key_info,
		|_| Ok(()),
	)
	.map_err(|_| YubiKeyError::FailedToGenerateSelfSignedCert)?;

	Ok(())
}

/// Sign data with the yubikey and return the signature as a raw bytes.
///
/// # Panics
/// Panics if `piv::sign_data` doesn't return a valid DER signature
pub fn sign_data(
	yubikey: &mut YubiKey,
	data: &[u8],
	pin: &[u8],
) -> Result<Vec<u8>, YubiKeyError> {
	// Get the public key for signing
	let signing_slot_cert = Certificate::read(yubikey, SIGNING_SLOT)
		.map_err(|_| YubiKeyError::CannotFindSigningKey)?;
	let public_key_info = signing_slot_cert.subject_pki();
	let encoded_point =
		extract_encoded_point(public_key_info.subject_public_key.as_bytes())?;
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
	let signing_encoded_point = extract_encoded_point(
		signing_public_key_info.subject_public_key.as_bytes(),
	)?;

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
	let key_agree_key_encoded_point = extract_encoded_point(
		key_agree_key_info.subject_public_key.as_bytes(),
	)?;

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
	bytes: Option<&[u8]>,
) -> Result<p256::EncodedPoint, YubiKeyError> {
	bytes
		.and_then(|el| p256::EncodedPoint::from_bytes(el).ok())
		.ok_or(YubiKeyError::FoundNonP256Key)
}

/// Generate an RFC5280 compliant serial number from a Cryptographically Secure
/// Pseudo Random Number Generator (CS-PRNG)
///
/// #Panics
///
/// Panics if the RNG fails, which should never happen.
fn generate_random_rfc5280_serial() -> [u8; 20] {
	let mut serial = [0u8; 20];
	OsRng.try_fill_bytes(&mut serial).expect(
		"The OsRng was unable to provide data, which should never happen",
	);
	// RFC5280 requires the serial to fit into 20 bytes and represent a positive signed integer,
	// which requires the most significant bit to be 0
	// Ensure this by masking a part the first byte
	serial[0] &= 0x7f;

	serial
}

// See the other code file(s) for integration tests
#[cfg(test)]
mod tests {
	use crate::yubikey::generate_random_rfc5280_serial;
	use x509_cert::serial_number::SerialNumber;

	#[test]
	fn test_rfc5280_serial_generation_success() {
		use x509_cert::certificate::Rfc5280;

		// the generation behavior is non-deterministic by design, try it a few dozen times
		const TEST_ITERATIONS: usize = 100;

		for _ in 0..TEST_ITERATIONS {
			let serial_data = generate_random_rfc5280_serial();

			// ensure most significant bit is 0
			assert_eq!(serial_data[0] & 0x80, 0);

			// test if serial conversion works
			let _serial: SerialNumber<Rfc5280> =
				SerialNumber::new(&serial_data).unwrap();
		}
	}
}
