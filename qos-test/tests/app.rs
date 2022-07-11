use std::{fs, process::Command};

use qos_test::MOCK_EPH_PATH;

const SAMPLE_APP_PATH: &str = "./target/release/sample-app";

#[tokio::test]
async fn sample_app_e2e() {
	let tmp = "./sample-app-e2e/";
	drop(fs::create_dir_all(tmp));

	let enclave_usock = "./dev-boot-e2e-tmp/enclave_sock.sock";
	let _app_usock = "./dev-boot-e2e-tmp/app_sock.sock";
	let secret_path = "./dev-boot-e2e-tmp/quorum.secret";
	let pivot_path = "./dev-boot-e2e-tmp/pivot.pivot";
	let manifest_path = "./dev-boot-e2e-tmp/manifest.manifest";

	let host_port = "3011";
	let host_ip = "127.0.0.1";

	// Start Enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			enclave_usock,
			"--quorum-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--ephemeral-file",
			// We pull the ephemeral key out of the attestation doc, which in
			// this case will be the mock attestation doc
			MOCK_EPH_PATH,
			"--mock",
			"--manifest-file",
			manifest_path,
		])
		.spawn()
		.unwrap();

	// Start host
	let mut host_child_process = Command::new("../target/debug/host_cli")
		.args([
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
			"--usock",
			enclave_usock,
		])
		.spawn()
		.unwrap();

	// Run `dangerous-dev-boot`
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"dangerous-dev-boot",
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
			"--pivot-path",
			SAMPLE_APP_PATH,
			"--restart-policy",
			"never",
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Query the secure app for the attestation doc

	// - make CLI command to query sample app for attestation docs

	// Clean up services
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
	drop(fs::remove_dir_all(tmp));
}
