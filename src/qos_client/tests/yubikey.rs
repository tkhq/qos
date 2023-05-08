use std::{
	fs::create_dir_all,
	io::{BufRead, BufReader},
	process::{Command, Stdio},
};

use borsh::BorshDeserialize;
use qos_client::yubikey::{
	generate_signed_certificate, import_key_and_generate_signed_certificate,
	key_agreement, sign_data, DEFAULT_PIN, KEY_AGREEMENT_SLOT, SIGNING_SLOT,
};
use qos_p256::{
	bytes_os_rng,
	encrypt::{Envelope, P256EncryptPair, P256EncryptPublic},
	sign::{P256SignPair, P256SignPublic},
	P256Pair, P256Public, P256_SECRET_LEN,
};
use qos_test_primitives::PathWrapper;
use yubikey::{MgmKey, TouchPolicy, YubiKey};

const DATA: &[u8] = b"test data";

// CAREFUL: Only run these tests when a test yubikey is plugged in - this will
// factory reset the yubikey.
//
// These are tests that require a physical card to be plugged in. The
// `provision_yubikey_works` requires tapping the yubikey. These tests are
// ignored because they require a yubikey to be plugged in.
//
// The tests are all run by this one function so we don't have issues trying to
// share the underlying PCSC connection to the yubikey. We need to disconnect
// the connection before we try to reconnect.
//
// To run this test: `cargo test -p qos_client yubikey -- --ignored`.
#[test]
#[ignore]
fn yubikey_tests() {
	let mut yubikey = YubiKey::open().unwrap();
	reset(&mut yubikey);

	signing_works(&mut yubikey);
	reset(&mut yubikey);

	key_agreement_works(&mut yubikey);
	reset(&mut yubikey);

	import_signing_works(&mut yubikey);
	reset(&mut yubikey);

	import_key_agreement_works(&mut yubikey);
	reset(&mut yubikey);

	// Dropping the yubikey should disconnect the underlying PCSC reader
	// connection. We want to disconnect before using the CLI
	// provision-yubikey command because that will try to open up a new
	// connection.
	drop(yubikey);

	provision_yubikey_works();

	// Reset the yubikey from provisioning
	let mut yubikey = YubiKey::open().unwrap();
	reset(&mut yubikey);
	drop(yubikey);

	advanced_provision_yubikey_works();

	let mut yubikey = YubiKey::open().unwrap();
	reset(&mut yubikey);
	drop(yubikey);

	provision_sign_and_verify();

	let mut yubikey = YubiKey::open().unwrap();
	reset(&mut yubikey);
	drop(yubikey);
}

fn key_agreement_works(yubikey: &mut YubiKey) {
	// generate encryption key on yubikey
	let public_bytes = generate_signed_certificate(
		yubikey,
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
		key_agreement(yubikey, &sender_pub_bytes, DEFAULT_PIN).unwrap();

	// do decryption
	let decrypted = public
		.decrypt_from_shared_secret(&envelope, &shared_secret[..])
		.unwrap();

	// confirm the output is correct
	assert_eq!(decrypted, DATA);
}

fn signing_works(yubikey: &mut YubiKey) {
	// generate signing key on yubikey
	let public_bytes = generate_signed_certificate(
		yubikey,
		SIGNING_SLOT,
		DEFAULT_PIN,
		MgmKey::default(),
		TouchPolicy::Never,
	)
	.unwrap();

	// get the public signing key
	let public = P256SignPublic::from_bytes(&public_bytes).unwrap();
	// use the yubikey to sign
	let signature = sign_data(yubikey, DATA, DEFAULT_PIN).unwrap();
	// verify the signature from the yubikey is correct
	assert!(public.verify(DATA, &signature).is_ok());
}

fn import_signing_works(yubikey: &mut YubiKey) {
	let secret = bytes_os_rng::<P256_SECRET_LEN>();
	let pair = P256SignPair::from_bytes(&secret).unwrap();
	let public = pair.public_key();

	import_key_and_generate_signed_certificate(
		yubikey,
		&secret,
		SIGNING_SLOT,
		DEFAULT_PIN,
		MgmKey::default(),
		TouchPolicy::Never,
	)
	.unwrap();

	let signature = sign_data(yubikey, DATA, DEFAULT_PIN).unwrap();
	// verify the signature from the yubikey is correct
	assert!(public.verify(DATA, &signature).is_ok());
}

fn import_key_agreement_works(yubikey: &mut YubiKey) {
	let secret = bytes_os_rng::<32>();
	let pair = P256EncryptPair::from_bytes(&secret).unwrap();
	let public = pair.public_key();

	import_key_and_generate_signed_certificate(
		yubikey,
		&secret,
		KEY_AGREEMENT_SLOT,
		DEFAULT_PIN,
		MgmKey::default(),
		TouchPolicy::Never,
	)
	.unwrap();

	// encrypt to that public key
	let envelope = public.encrypt(DATA).unwrap();

	// get the sender eph key from the encryption envelope
	let sender_pub_bytes = {
		let decoded = Envelope::try_from_slice(&envelope).unwrap();
		decoded.ephemeral_sender_public
	};

	// use the yubikey to compute shared secret with sender eph key
	let shared_secret =
		key_agreement(yubikey, &sender_pub_bytes, DEFAULT_PIN).unwrap();

	// do decryption
	let decrypted = public
		.decrypt_from_shared_secret(&envelope, &shared_secret[..])
		.unwrap();

	// confirm the output is correct
	assert_eq!(decrypted, DATA);
}

fn provision_yubikey_works() {
	let tmp_dir: PathWrapper = "/tmp/provision_yubikey_works".into();
	let pub_path: PathWrapper =
		"/tmp/provision_yubikey_works/yubikey.pub".into();

	// Create the temporary directory where we write the yubikey
	std::fs::create_dir(&*tmp_dir).unwrap();

	assert!(Command::new("../target/debug/qos_client")
		.arg("provision-yubikey")
		.arg("--pub-path")
		.arg(&*pub_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check that public keys where written
	{
		let hex_bytes = std::fs::read(&*pub_path).unwrap();
		let hex = String::from_utf8(hex_bytes).unwrap();
		let bytes = qos_hex::decode(&hex).unwrap();
		assert!(P256Public::from_bytes(&bytes).is_ok());
		P256Public::from_bytes(&bytes).unwrap();
	}
}

fn advanced_provision_yubikey_works() {
	let tmp_dir: PathWrapper = "/tmp/advanced_provision_yubikey_works".into();
	let master_seed_path: PathWrapper =
		"/tmp/advanced_provision_yubikey_works/yubikey.master.secret".into();
	let pub_path: PathWrapper =
		"/tmp/advanced_provision_yubikey_works/yubikey.pub".into();

	// Create the temporary directory where we write the yubikey
	std::fs::create_dir(&*tmp_dir).unwrap();

	assert!(Command::new("../target/debug/qos_client")
		.arg("generate-file-key")
		.arg("--master-seed-path")
		.arg(&*master_seed_path)
		.arg("--pub-path")
		.arg(&*pub_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	assert!(Command::new("../target/debug/qos_client")
		.arg("advanced-provision-yubikey")
		.arg("--master-seed-path")
		.arg(&*master_seed_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check that public keys where written
	let public = {
		let hex_bytes = std::fs::read(&*pub_path).unwrap();
		let hex = String::from_utf8(hex_bytes).unwrap();
		let bytes = qos_hex::decode(&hex).unwrap();
		P256Public::from_bytes(&bytes).unwrap()
	};

	let mut yubikey = YubiKey::open().unwrap();
	let yubi_pub = qos_client::yubikey::pair_public_key(&mut yubikey).unwrap();
	drop(yubikey);

	assert_eq!(public.to_bytes(), yubi_pub);

	let pair = P256Pair::from_hex_file(&*master_seed_path).unwrap();

	assert!(pair.public_key() == public)
}

fn provision_sign_and_verify() {
	let tmp_dir: PathWrapper = "/tmp/provision_sign_and_verify".into();
	create_dir_all(&*tmp_dir).unwrap();
	let pub_path: PathWrapper =
		"/tmp/provision_sign_and_verify/yubikey.pub".into();
	let signature_path = "/tmp/provision_sign_and_verify/signature";
	let payload_path = "/tmp/provision_sign_and_verify/payload";

	assert!(Command::new("../target/debug/qos_client")
		.arg("provision-yubikey")
		.arg("--pub-path")
		.arg(&*pub_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let data_hex = qos_hex::encode(DATA);
	let mut child = Command::new("../target/debug/qos_client")
		.arg("yubikey-sign")
		.arg("--payload")
		.arg(&data_hex)
		.stdout(Stdio::piped())
		.spawn()
		.unwrap();

	let mut stdout = {
		let stdout = child.stdout.as_mut().unwrap();
		let stdout_reader = BufReader::new(stdout);
		stdout_reader.lines()
	};

	stdout.next();
	let signature = stdout.next().unwrap().unwrap();

	std::fs::write(payload_path, DATA).unwrap();
	std::fs::write(signature_path, signature).unwrap();

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-verify")
		.arg("--payload-path")
		.arg(payload_path)
		.arg("--signature-path")
		.arg(signature_path)
		.arg("--pub-path")
		.arg(&*pub_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
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
