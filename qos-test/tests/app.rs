use std::{fs, process::Command};

use test_primitives::ChildWrapper;

const SAMPLE_APP_PATH: &str = "../target/debug/sample_app";

#[ignore]
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

	let host_port = test_primitives::find_free_port().unwrap();
	let host_ip = "127.0.0.1";

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/core_cli")
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
			.unwrap()
			.into();

	// Start host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/host_cli")
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				host_ip,
				"--usock",
				enclave_usock,
			])
			.spawn()
			.unwrap()
			.into();

	// Run `dangerous-dev-boot`
	let pivot_args = format!("[--usock,{app_usock},--quorum-file,{quorum_path},--ephemeral-file,{eph_path},--manifest-file,{manifest_path}]");
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"dangerous-dev-boot",
			"--host-port",
			&host_port.to_string(),
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

	test_primitives::wait_until_port_is_bound(host_port);

	assert!(Command::new("../target/debug/client_cli")
		.args([
			"app-read-files",
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			host_ip,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Clean up services
	drop(fs::remove_dir_all(tmp));
}
