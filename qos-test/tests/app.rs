use std::{fs, process::Command};

use qos_test::MOCK_EPH_PATH;

const SAMPLE_APP_PATH: &str = "../target/debug/sample_app";

#[tokio::test]
async fn sample_app_e2e() {
	let tmp = "./sample-app-e2e-tmp/";
	drop(fs::create_dir_all(tmp));

	let enclave_usock = "./sample-app-e2e-tmp/enclave_sock.sock";
	let app_usock = "./sample-app-e2e-tmp/app_sock.sock";
	let quorum_path = "./sample-app-e2e-tmp/quorum.secret";
	let pivot_path = "./sample-app-e2e-tmp/pivot.pivot";
	let manifest_path = "./sample-app-e2e-tmp/manifest.manifest";
	let eph_path = "./sample-app-e2e-tmp/eph.secret";

	let host_port = "3232";
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
			eph_path,
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

	// Run `dangerous-dev-boot`
	let pivot_args = format!("[--usock,{app_usock},--quorum-file,{quorum_path},--ephemeral-file,{MOCK_EPH_PATH},--manifest-file,{manifest_path}]");
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
			&pivot_args[..],
			"--unsafe-eph-path-override",
			eph_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	std::thread::sleep(std::time::Duration::from_secs(2));

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
