use std::{fs, process::Command};

use qos_test::MOCK_EPH_PATH;

const SAMPLE_APP_PATH: &str = "../target/debug/sample-app";

#[tokio::test]
async fn sample_app_e2e() {
	let tmp = "./sample-app-e2e-tmp/";
	drop(fs::create_dir_all(tmp));

	let enclave_usock = "./sample-app-e2e-tmp/enclave_sock.sock";
	let app_usock = "./sample-app-e2e-tmp/app_sock.sock";
	let quorum_path = "./sample-app-e2e-tmp/quorum.secret";
	let pivot_path = "./sample-app-e2e-tmp/pivot.pivot";
	let manifest_path = "./sample-app-e2e-tmp/manifest.manifest";

	let host_port = "3011";
	let host_ip = "127.0.0.1";

	// Start Enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			enclave_usock,
			"--quorum-file",
			quorum_path,
			"--pivot-file",
			pivot_path,
			"--ephemeral-file",
			// We pull the ephemeral key out of the attestation doc, which in
			// this case will be the mock attestation doc
			MOCK_EPH_PATH,
			"--mock",
			"--manifest-file",
			manifest_path,
			"--app-usock",
			app_usock,
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

	// Query the secure app for the attestation doc
	// assert!(Command::new("../target/debug/sample_app")
	// 	.args([
	// 		"--usock",
	// 		app_usock,
	// 		"--quorum-file",
	// 		quorum_path,
	// 		"--pivot-file",
	// 		pivot_path,
	// 		"--ephemeral-file",
	// 		MOCK_EPH_PATH,
	// 		"--manifest-file",
	// 		manifest_path,
	// 	])
	// 	.spawn()
	// 	.unwrap()
	// 	.wait()
	// 	.unwrap()
	// 	.success());

	// Run `dangerous-dev-boot`
	let pivot_args = format!("[--usock,{app_usock},--quorum-file,{pivot_path},--ephemeral-file,{MOCK_EPH_PATH},--manifest-file,{manifest_path}]");
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
			"--pivot-args",
			&pivot_args[..]
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	std::thread::sleep(std::time::Duration::from_secs(5));

	assert!(Command::new("../target/debug/client_cli")
		.args([
			"app-read-files",
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Clean up services
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
	drop(fs::remove_dir_all(tmp));
}
