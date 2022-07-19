use std::{fs, path::Path, process::Command};

use qos_core::protocol::services::boot::MOCK_EPH_PATH_TEST;
use qos_test::{MOCK_EPH_PATH, PIVOT_OK3_PATH, PIVOT_OK3_SUCCESS_FILE};

#[tokio::test]
async fn dev_boot_e2e() {
	let tmp = "./dev-boot-e2e-tmp/";
	drop(fs::create_dir_all(tmp));
	let usock = "./dev-boot-e2e-tmp/sock.sock";
	let secret_path = "./dev-boot-e2e-tmp/quorum.secret";
	let pivot_path = "./dev-boot-e2e-tmp/pivot.pivot";
	let manifest_path = "./dev-boot-e2e-tmp/manifest.manifest";
	let eph_path = "./dev-boot-e2e-tmp/eph.secret";

	let host_port = "3010";
	let host_ip = "127.0.0.1";

	// Start Enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--quorum-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--ephemeral-file",
			// We pull the ephemeral key out of the attestation doc, which in
			// this case will be the mock attestation doc
			// MOCK_EPH_PATH,
			eph_path,
			"--mock",
			"--manifest-file",
			manifest_path,
		])
		.spawn()
		.unwrap();

	// Start Host
	let mut host_child_process = Command::new("../target/debug/host_cli")
		.args([
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
			"--usock",
			usock,
		])
		.spawn()
		.unwrap();

	// Run `dangerous-dev-boot`
	let res = Command::new("../target/debug/client_cli")
		.args([
			"dangerous-dev-boot",
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
			"--pivot-path",
			PIVOT_OK3_PATH,
			"--restart-policy",
			"never",
			"--pivot-args",
			"[--msg,vapers-only]",
			"--unsafe-eph-path-override",
			eph_path

		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	// Give the coordinator time to pivot
	std::thread::sleep(std::time::Duration::from_secs(2));

	// Clean up services
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
	drop(fs::remove_dir_all(tmp));

	// Make sure pivot ran
	assert!(Path::new(PIVOT_OK3_SUCCESS_FILE).exists());
	assert!(res.success());

	let contents = fs::read(PIVOT_OK3_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), "vapers-only");
	fs::remove_file(PIVOT_OK3_SUCCESS_FILE).unwrap();
}
