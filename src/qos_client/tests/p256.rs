use std::{
	io::{BufRead, BufReader},
	path::PathBuf,
	process::{Command, Stdio},
};

use qos_test_primitives::PathWrapper;

const DATA: &str = "test data";
const MOCK_PRIMARY_SEED_PATH: &str = "./tests/mock/primary.secret";
const MOCK_PRIMARY_PUB_PATH: &str = "./tests/mock/primary.pub";
// If this is updated there is a breaking change to our crypto
const EXPECTED_SIGNATURE: &str = "36c7f22c3831a32b8c8a9e823641e7df591c6e92848e7baa54f66d65963d15eaf02abbf5f01f99a8dddfe7a35453a4df486a708ffa3ef2d8159d4d0763f5ee89";

#[test]
fn p256_sign_verify_roundtrip() {
	let mut child = Command::new("../target/debug/qos_client")
		.arg("p256-sign")
		.arg("--payload")
		.arg(DATA)
		.arg("--master-seed-path")
		.arg(MOCK_PRIMARY_SEED_PATH)
		.stdout(Stdio::piped())
		.spawn()
		.unwrap();

	let mut stdout = {
		let stdout = child.stdout.as_mut().unwrap();
		let stdout_reader = BufReader::new(stdout);
		stdout_reader.lines()
	};
	let signature = stdout.next().unwrap().unwrap();
	assert_eq!(signature, EXPECTED_SIGNATURE);

	assert!(Command::new("../target/debug/qos_client")
		.arg("p256-verify")
		.arg("--payload")
		.arg(DATA)
		.arg("--signature")
		.arg(signature)
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
