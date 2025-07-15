use std::{process::Command, time::Duration};

use integration::PIVOT_OK_PATH;
use qos_test_primitives::{ChildWrapper, PathWrapper};

const TEST_ENCLAVE_SOCKET: &str = "/tmp/qos_host_test.enclave.sock";

#[test]
fn connects_and_gets_info() {
	let _qos_host: ChildWrapper = Command::new("../target/debug/qos_host")
		.arg("--usock")
		.arg(TEST_ENCLAVE_SOCKET)
		.arg("--host-ip")
		.arg("127.0.0.1")
		.arg("--host-port")
		.arg("3323")
		.arg("--socket-timeout")
		.arg("50") // ms
		.spawn()
		.unwrap()
		.into();

	std::thread::sleep(Duration::from_millis(100)); // let the qos_host start

	let r = ureq::get("http://127.0.0.1:3323/qos/enclave-info").call();
	assert!(r.is_err()); // expect 500 here

	let secret_path: PathWrapper = "/tmp/qos_host_reaper_works.secret".into();
	// let eph_path = "reaper_works.eph.key";
	let manifest_path: PathWrapper =
		"/tmp/qos_host_reaper_works.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(std::fs::remove_file(&*secret_path));

	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				TEST_ENCLAVE_SOCKET,
				"--quorum-file",
				&*secret_path,
				"--pivot-file",
				PIVOT_OK_PATH,
				"--ephemeral-file",
				"eph_path",
				"--mock",
				"--manifest-file",
				&*manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_millis(500));

	let r = ureq::get("http://127.0.0.1:3323/qos/enclave-info").call();
	assert!(r.is_ok()); // expect 200 here
}
