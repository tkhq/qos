//! Yubikey interfaces

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
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
const ALGO: AlgorithmId = AlgorithmId::EccP256;

/// Errors for yubikey interaction
#[derive(Debug, PartialEq)]
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

fn extract_encoded_point(
	public_key_info: &PublicKeyInfo,
) -> Result<p256::EncodedPoint, YubiKeyError> {
	match public_key_info {
		PublicKeyInfo::EcP256(encoded_point) => Ok(*encoded_point),
		_ => Err(YubiKeyError::FoundNonP256Key),
	}
}
