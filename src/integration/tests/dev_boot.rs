use std::{fs, path::Path, process::Command};

use integration::{LOCAL_HOST, PIVOT_OK3_PATH, PIVOT_OK3_SUCCESS_FILE};
use qos_test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test(flavor = "multi_thread")]
async fn dev_boot_e2e() {
	let tmp = PathWrapper::from("/tmp/dev-boot-e2e-tmp");
	drop(fs::create_dir_all(&*tmp));
	let _ = PathWrapper::from(PIVOT_OK3_SUCCESS_FILE);
	let usock = tmp.join("sock.sock");
	let secret_path = tmp.join("quorum.secret");
	let pivot_path = tmp.join("pivot.pivot");
	let manifest_path = tmp.join("manifest.manifest");
	let eph_path = tmp.join("eph.secret");

	let host_port = qos_test_primitives::find_free_port().unwrap();

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new(integration::QOS_CORE_PATH)
			.args([
				"--usock",
				usock.to_str().unwrap(),
				"--quorum-file",
				secret_path.to_str().unwrap(),
				"--pivot-file",
				pivot_path.to_str().unwrap(),
				"--ephemeral-file",
				eph_path.to_str().unwrap(),
				"--mock",
				"--manifest-file",
				manifest_path.to_str().unwrap(),
			])
			.spawn()
			.unwrap()
			.into();

	// Start Host
	let mut _host_child_process: ChildWrapper =
		Command::new(integration::QOS_HOST_PATH)
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				usock.to_str().unwrap(),
				"--socket-timeout",
				"15000",
			])
			.spawn()
			.unwrap()
			.into();

	qos_test_primitives::wait_until_port_is_bound(host_port);

	// Run `dangerous-dev-boot`
	let res = Command::new(integration::QOS_CLIENT_PATH)
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
			eph_path.to_str().unwrap(),
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	// Give the coordinator time to pivot
	tokio::time::sleep(std::time::Duration::from_secs(2)).await;

	// Make sure pivot ran
	assert!(Path::new(PIVOT_OK3_SUCCESS_FILE).exists());
	assert!(res.success());

	let contents = fs::read(PIVOT_OK3_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), "vapers-only");
	fs::remove_file(PIVOT_OK3_SUCCESS_FILE).unwrap();
}
