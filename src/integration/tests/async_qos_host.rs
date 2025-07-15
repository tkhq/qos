use std::{process::Command, time::Duration};

use integration::PIVOT_OK_PATH;
use qos_test_primitives::{ChildWrapper, PathWrapper};

const TEST_ENCLAVE_SOCKET: &str = "/tmp/async_qos_host_test/enclave.sock";

#[tokio::test]
async fn connects_and_gets_info() {
	// prep sock pool dir
	std::fs::create_dir_all("/tmp/async_qos_host_test").unwrap();

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

	tokio::time::sleep(Duration::from_millis(100)).await; // let the qos_host start

	let r = ureq::get("http://127.0.0.1:3323/qos/enclave-info").call();
	assert!(r.is_err()); // expect 500 here

	let enclave_socket = format!("{TEST_ENCLAVE_SOCKET}_0"); // manually pick the 1st one
	let secret_path: PathWrapper = "./async_qos_host_test.secret".into();
	// let eph_path = "reaper_works.eph.key";
	let manifest_path: PathWrapper = "async_qos_host_test.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(std::fs::remove_file(&*secret_path));
	// Remove the socket file if it exists as well, in case of bad crashes
	drop(std::fs::remove_file(&enclave_socket));

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
	tokio::time::sleep(std::time::Duration::from_millis(200)).await;

	let r = ureq::get("http://127.0.0.1:3323/qos/enclave-info").call();
	assert!(r.is_ok()); // expect 200 here
}
