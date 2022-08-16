use std::{fs, path::Path, process::Command};

use qos_test::{PIVOT_OK3_PATH, PIVOT_OK3_SUCCESS_FILE, LOCAL_HOST};
use test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test]
async fn dev_boot_e2e() {
	let tmp: PathWrapper = "/tmp/dev-boot-e2e-tmp".into();
	drop(fs::create_dir_all(*tmp));
	let usock: PathWrapper = "/tmp/dev-boot-e2e-tmp/sock.sock".into();
	let secret_path: PathWrapper = "/tmp/dev-boot-e2e-tmp/quorum.secret".into();
	let pivot_path: PathWrapper = "/tmp/dev-boot-e2e-tmp/pivot.pivot".into();
	let manifest_path: PathWrapper = "/tmp/dev-boot-e2e-tmp/manifest.manifest".into();
	let eph_path: PathWrapper = "/tmp/dev-boot-e2e-tmp/eph.secret".into();

	let host_port = test_primitives::find_free_port().unwrap();

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/core_cli")
			.args([
				"--usock",
				*usock,
				"--quorum-file",
				*secret_path,
				"--pivot-file",
				*pivot_path,
				"--ephemeral-file",
				*eph_path,
				"--mock",
				"--manifest-file",
				*manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// Start Host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/host_cli")
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				*usock,
			])
			.spawn()
			.unwrap()
			.into();

	test_primitives::wait_until_port_is_bound(host_port);

	// Run `dangerous-dev-boot`
	let res = Command::new("../target/debug/client_cli")
		.args([
			"dangerous-dev-boot",
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--pivot-path",
			PIVOT_OK3_PATH,
			"--restart-policy",
			"never",
			"--pivot-args",
			"[--msg,vapers-only]",
			"--unsafe-eph-path-override",
			*eph_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	// Give the coordinator time to pivot
	std::thread::sleep(std::time::Duration::from_secs(2));

	// Make sure pivot ran
	assert!(Path::new(PIVOT_OK3_SUCCESS_FILE).exists());
	assert!(res.success());

	let contents = fs::read(PIVOT_OK3_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), "vapers-only");
	fs::remove_file(PIVOT_OK3_SUCCESS_FILE).unwrap();
}
