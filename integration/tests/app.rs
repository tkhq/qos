use std::{fs, process::Command};

use integration::LOCAL_HOST;
use qos_test_primitives::{ChildWrapper, PathWrapper};

const SAMPLE_APP_PATH: &str = "../target/debug/sample-app";

#[tokio::test]
async fn sample_app_e2e() {
	let tmp: PathWrapper = "/tmp/sample-app-e2e".into();
	drop(fs::create_dir_all(*tmp));

	let enclave_usock: PathWrapper =
		"/tmp/sample-app-e2e/enclave_sock.sock".into();
	let app_usock: PathWrapper = "/tmp/sample-app-e2e/app_sock.sock".into();
	let quorum_path: PathWrapper = "/tmp/sample-app-e2e/quorum.secret".into();
	let pivot_path: PathWrapper = "/tmp/sample-app-e2e/pivot.pivot".into();
	let manifest_path: PathWrapper =
		"/tmp/sample-app-e2e/manifest.manifest".into();
	let eph_path: PathWrapper = "/tmp/sample-app-e2e/eph.secret".into();

	let host_port = qos_test_primitives::find_free_port().unwrap();

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				*enclave_usock,
				"--quorum-file",
				*quorum_path,
				"--pivot-file",
				*pivot_path,
				"--ephemeral-file",
				*eph_path,
				"--mock",
				"--manifest-file",
				*manifest_path,
				"--app-usock",
				*app_usock,
			])
			.spawn()
			.unwrap()
			.into();

	// Start host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/qos-host")
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				*enclave_usock,
			])
			.spawn()
			.unwrap()
			.into();

	// Run `dangerous-dev-boot`
	let pivot_args = format!(
		"[--usock,{},--quorum-file,{},--ephemeral-file,{},--manifest-file,{}]",
		*app_usock, *quorum_path, *eph_path, *manifest_path
	);
	assert!(Command::new("../target/debug/qos-client")
		.args([
			"dangerous-dev-boot",
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--pivot-path",
			SAMPLE_APP_PATH,
			"--restart-policy",
			"never",
			"--pivot-args",
			&pivot_args[..],
			"--unsafe-eph-path-override",
			*eph_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	qos_test_primitives::wait_until_port_is_bound(host_port);

	assert!(Command::new("../target/debug/qos-client")
		.args([
			"app-read-files",
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
}
