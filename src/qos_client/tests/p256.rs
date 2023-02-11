use std::{path::PathBuf, process::Command};

use qos_test_primitives::PathWrapper;

const DATA: &str = "test data";
const MOCK_PRIMARY_SEED_PATH: &str = "./tests/mock/primary.secret.keep";
const MOCK_PRIMARY_PUB_PATH: &str = "./tests/mock/primary.pub";
// If this is updated there is a breaking change to the commands api
const EXPECTED_SIGNATURE: &str = "36c7f22c3831a32b8c8a9e823641e7df591c6e92848e7baa54f66d65963d15eaf02abbf5f01f99a8dddfe7a35453a4df486a708ffa3ef2d8159d4d0763f5ee89";

#[test]
fn p256_sign_verify_roundtrip() {
	let tmp: PathWrapper = "/tmp/p256_sign_verify_roundtrip".into();
	std::fs::create_dir_all(&*tmp).unwrap();

	let payload_path = "/tmp/p256_sign_verify_roundtrip/payload";
	let signature_path = "/tmp/p256_sign_verify_roundtrip/signature";

	std::fs::write(payload_path, DATA).unwrap();
	// Sanity check the signature output doesn't already exist
	assert!(!PathBuf::from(signature_path).exists());

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-sign")
		.arg("--payload-path")
		.arg(payload_path)
		.arg("--signature-path")
		.arg(signature_path)
		.arg("--master-seed-path")
		.arg(MOCK_PRIMARY_SEED_PATH)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let signature = std::fs::read_to_string(signature_path).unwrap();
	assert_eq!(EXPECTED_SIGNATURE, signature);

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-verify")
		.arg("--payload-path")
		.arg(payload_path)
		.arg("--signature-path")
		.arg(signature_path)
		.arg("--pub-path")
		.arg(MOCK_PRIMARY_PUB_PATH)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
}

#[test]
fn p256_asymmetric_encrypt_decrypt_roundtrip() {
	let tmp: PathWrapper =
		"/tmp/p256_asymmetric_encrypt_decrypt_roundtrip".into();
	std::fs::create_dir_all(&*tmp).unwrap();

	let plaintext_input_path =
		"/tmp/p256_asymmetric_encrypt_decrypt_roundtrip/plaintext_input";
	std::fs::write(plaintext_input_path, DATA.as_bytes()).unwrap();
	let ciphertext_path =
		"/tmp/p256_asymmetric_encrypt_decrypt_roundtrip/ciphertext";
	// Sanity check the ciphertext output doesn't already exist
	assert!(!PathBuf::from(ciphertext_path).exists());

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-asymmetric-encrypt")
		.arg("--plaintext-path")
		.arg(plaintext_input_path)
		.arg("--ciphertext-path")
		.arg(ciphertext_path)
		.arg("--pub-path")
		.arg(MOCK_PRIMARY_PUB_PATH)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let plaintext_output_path =
		"/tmp/p256_asymmetric_encrypt_decrypt_roundtrip/plaintext_output";
	assert!(!PathBuf::from(plaintext_output_path).exists());

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-asymmetric-decrypt")
		.arg("--plaintext-path")
		.arg(plaintext_output_path)
		.arg("--ciphertext-path")
		.arg(ciphertext_path)
		.arg("--master-seed-path")
		.arg(MOCK_PRIMARY_SEED_PATH)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let decrypted = std::fs::read(plaintext_output_path).unwrap();

	assert_eq!(decrypted, DATA.as_bytes());
}
