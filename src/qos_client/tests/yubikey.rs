use borsh::BorshDeserialize;
use qos_client::yubikey::{
	generate_signed_certificate, key_agreement, KEY_AGREEMENT_SLOT,
};
use qos_p256::encrypt::{Envelope, P256EncryptPublic};
use yubikey::{MgmKey, YubiKey};

const DATA: &[u8] = b"test data";

#[test]
fn key_agreement_works() {
	let mut yubikey = YubiKey::open().unwrap();

	// generate encryption key on yubikey
	let public_bytes = generate_signed_certificate(
		&mut yubikey,
		KEY_AGREEMENT_SLOT,
		b"123456",
		MgmKey::default(),
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
		key_agreement(&mut yubikey, &sender_pub_bytes, b"123456").unwrap();

	// do decryption
	let decrypted = public
		.decrypt_from_shared_secret(&envelope, &shared_secret[..])
		.unwrap();

	dbg!(String::from_utf8(decrypted.clone()));

	// confirm the output is correct
	assert_eq!(decrypted, DATA);
}
