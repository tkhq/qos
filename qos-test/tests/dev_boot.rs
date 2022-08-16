use std::{fs, path::Path, process::Command};

use qos_test::{PIVOT_OK3_PATH, PIVOT_OK3_SUCCESS_FILE};
use test_primitives::ChildWrapper;

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
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/core_cli")
			.args([
				"--usock",
				usock,
				"--quorum-file",
				secret_path,
				"--pivot-file",
				pivot_path,
				"--ephemeral-file",
				eph_path,
				"--mock",
				"--manifest-file",
				manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// Start Host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/host_cli")
			.args([
				"--host-port",
				host_port,
				"--host-ip",
				host_ip,
				"--usock",
				usock,
			])
			.spawn()
			.unwrap()
			.into();

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
			eph_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	// Give the coordinator time to pivot
	std::thread::sleep(std::time::Duration::from_secs(2));

	// Clean up services
	drop(fs::remove_dir_all(tmp));

	// Make sure pivot ran
	assert!(Path::new(PIVOT_OK3_SUCCESS_FILE).exists());
	assert!(res.success());

	let contents = fs::read(PIVOT_OK3_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), "vapers-only");
	fs::remove_file(PIVOT_OK3_SUCCESS_FILE).unwrap();
}
