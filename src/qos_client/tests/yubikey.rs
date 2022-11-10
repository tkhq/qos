use std::sync::Mutex;

use borsh::BorshDeserialize;
use qos_client::yubikey::{
	generate_signed_certificate, key_agreement, sign_data, KEY_AGREEMENT_SLOT,
	SIGNING_SLOT,
};
use qos_p256::{
	encrypt::{Envelope, P256EncryptPublic},
	sign::P256SignPublic,
};
use yubikey::{MgmKey, TouchPolicy, YubiKey};

const DATA: &[u8] = b"test data";
const DEFAULT_PIN: &[u8] = b"123456";

lazy_static::lazy_static! {
	/// Provide thread-safe access to a YubiKey
	static ref YUBIKEY: Mutex<YubiKey> = init_yubikey();
}

/// One-time test initialization and setup
// Taken from https://github.com/iqlusioninc/yubikey.rs/blob/main/tests/integration.rs
fn init_yubikey() -> Mutex<YubiKey> {
	let yubikey = YubiKey::open().unwrap();

	Mutex::new(yubikey)
}

#[test]
#[ignore]
fn key_agreement_works() {
	let mut yubikey = YUBIKEY.lock().unwrap();
	reset(&mut yubikey);

	// generate encryption key on yubikey
	let public_bytes = generate_signed_certificate(
		&mut yubikey,
		KEY_AGREEMENT_SLOT,
		DEFAULT_PIN,
		MgmKey::default(),
		TouchPolicy::Never,
	)
	.unwrap();

	// get the public encryption key
	let public = P256EncryptPublic::from_bytes(&public_bytes).unwrap();

	// encrypt to that public key
	let envelope = public.encrypt(DATA).unwrap();

	// get the sender eph key from the encryption envelope
	let sender_pub_bytes = {
		let decoded = Envelope::try_from_slice(&envelope).unwrap();
		decoded.ephemeral_sender_public
	};

	// use the yubikey to compute shared secret with sender eph key
	let shared_secret =
		key_agreement(&mut yubikey, &sender_pub_bytes, DEFAULT_PIN).unwrap();

	// do decryption
	let decrypted = public
		.decrypt_from_shared_secret(&envelope, &shared_secret[..])
		.unwrap();

	// confirm the output is correct
	assert_eq!(decrypted, DATA);

	reset(&mut yubikey);
}

#[test]
#[ignore]
fn signing_works() {
	let mut yubikey = YUBIKEY.lock().unwrap();
	reset(&mut yubikey);

	// generate signing key on yubikey
	let public_bytes = generate_signed_certificate(
		&mut yubikey,
		SIGNING_SLOT,
		DEFAULT_PIN,
		MgmKey::default(),
		TouchPolicy::Never,
	)
	.unwrap();

	// get the public signing key
	let public = P256SignPublic::from_bytes(&public_bytes).unwrap();
	// use the yubikey to sign
	let signature = sign_data(&mut yubikey, DATA, DEFAULT_PIN).unwrap();
	// verify the signature from the yubikey is correct
	assert!(public.verify(DATA, &signature).is_ok());

	reset(&mut yubikey);
}

fn reset(yubikey: &mut YubiKey) {
	// Pins need to be blocked before device can be reset
	for _ in 0..3 {
		assert!(yubikey.authenticate(MgmKey::generate()).is_err());
		assert!(yubikey.verify_pin(b"000000").is_err());
	}

	assert!(yubikey.block_puk().is_ok());

	yubikey.reset_device().unwrap();
}
