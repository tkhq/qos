use std::{fs::File, path::Path, process::Command};

use qos_client::request;
use qos_core::{
	coordinator::Coordinator,
	protocol::{Load, ProtocolMsg, Provision},
};
use qos_crypto::shares_generate;

const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";

#[tokio::test]
async fn coordinator_e2e() {
	let usock = "coordinator_e2e.sock";
	let host_port = "3007";
	let host_ip = "127.0.0.1";
	let message_url = format!("http://{}:{}/message", host_ip, host_port);
	let secret_file = "./coordinator_e2e.secret";
	let pivot_file = "./coordinator_e2e.pivot";

	// For our sanity, make sure the files that should be artifacts only of
	// this test are not present.
	let _ = std::fs::remove_file(qos_test::PIVOT_OK_SUCCESS_FILE);
	let _ = std::fs::remove_file(pivot_file);
	let _ = std::fs::remove_file(secret_file);

	// **Start enclave**
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--secret-file",
			secret_file,
			"--pivot-file",
			pivot_file,
			"--mock",
			"true",
		])
		.spawn()
		.unwrap();

	// **Start host**
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

	// -- Make sure the enclave and host have time to boot
	std::thread::sleep(std::time::Duration::from_secs(1));

	// **Load the executable**

	// -- Convert the executable to bytes
	let pivot_bytes = std::fs::read(PIVOT_OK_PATH).unwrap();

	// -- Send that executable via the ProtocolLoad message
	let load_msg = ProtocolMsg::LoadRequest(Load {
		executable: pivot_bytes,
		signatures: vec![],
	});
	let response = request::post(&message_url, load_msg).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	// -- Check that the executable got written as a file
	assert!(Path::new(pivot_file).exists());

	// **Post user shards to provision**

	// -- Create shards
	let secret = b"only the real vape nationers would get this";
	let n = 6;
	let k = 3;
	let all_shares = shares_generate(secret, n, k);

	// -- For each shard send it and expect a success response
	for share in all_shares.into_iter().take(k) {
		let provision_msg = ProtocolMsg::ProvisionRequest(Provision { share });
		let response = request::post(&message_url, provision_msg).unwrap();
		assert_eq!(response, ProtocolMsg::SuccessResponse);
	}

	// -- Send reconstruct request to create secret file from shards
	let response =
		request::post(&message_url, ProtocolMsg::ReconstructRequest).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);
	assert!(Path::new(secret_file).exists());

	// -- Wait for the coordinator to check if the both the secret and pivot
	// exist
	std::thread::sleep(std::time::Duration::from_secs(5));

	// -- Kill the enclave and host since we don't need them anymore
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();

	// -- Check that the pivot ran
	// Note that PIVOT_OK_SUCCESS_FILE gets written by the `pivot_ok` binary
	// when it runs.
	assert!(std::fs::remove_file(qos_test::PIVOT_OK_SUCCESS_FILE).is_ok());
}

#[test]
fn coordinator_works() {
	let secret_path =
		"./coordinator_exits_cleanly_with_non_panicking_executable.secret";
	// For our sanity, ensure the secret does not yet exist. (Errors if file
	// doesn't exist)
	let _ = std::fs::remove_file(secret_path);
	assert!(File::open(PIVOT_OK_PATH).is_ok(),);

	let opts: Vec<_>  = [
		"--usock",
		"./coordinator_exits_cleanly_with_non_panicking_executable.sock",
		"--mock",
		"true",
		"--secret-file",
		secret_path,
		"--pivot-file",
		PIVOT_OK_PATH,
	]
	.into_iter()
	.map(String::from)
	.collect();

	let coordinator_handle =
		std::thread::spawn(move || Coordinator::execute(opts.into()));

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	std::fs::write(secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the coordinator executed successfully.
	coordinator_handle.join().unwrap();

	// Clean up
	std::fs::remove_file(secret_path).unwrap();
}

#[test]
fn coordinator_handles_non_zero_exits() {
	let secret_path =
		"./coordinator_keeps_re_spawning_pivot_executable_that_panics.secret";
	// For our sanity, ensure the secret does not yet exist
	let _ = std::fs::remove_file(secret_path);
	assert!(File::open(PIVOT_ABORT_PATH).is_ok(),);

	let opts: Vec<_> = [
		"--usock",
		"./coordinator_keeps_re_spawning_pivot_executable_that_panics.sock",
		"--mock",
		"true",
		"--secret-file",
		secret_path,
		"--pivot-file",
		PIVOT_ABORT_PATH,
	]
	.into_iter()
	.map(String::from)
	.collect();

	let coordinator_handle =
		std::thread::spawn(move || Coordinator::execute(opts.into()));

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	std::fs::write(secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the coordinator has enough time to detect the secret now exists
	std::thread::sleep(std::time::Duration::from_secs(1));

	for _ in 0..3 {
		std::thread::sleep(std::time::Duration::from_millis(100));
		// Check that the coordinator is still running, presumably restarting
		// the child process
		assert!(!coordinator_handle.is_finished());
	}
}

#[test]
fn coordinator_handles_panic() {
	let secret_path = "./coordinator_handles_panics.secret";
	// For our sanity, ensure the secret does not yet exist. (Errors if file
	// doesn't exist)
	let _ = std::fs::remove_file(secret_path);
	assert!(File::open(PIVOT_PANIC_PATH).is_ok(),);

	let opts: Vec<_>  = [
		"--usock",
		"./coordinator_handles_panics.sock",
		"--mock",
		"true",
		"--secret-file",
		secret_path,
		"--pivot-file",
		PIVOT_PANIC_PATH,
	]
	.into_iter()
	.map(String::from)
	.collect::<Vec<String>>();

	let coordinator_handle =
		std::thread::spawn(move || Coordinator::execute(opts.into()));

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	std::fs::write(secret_path, b"super dank tank secret tech").unwrap();

	for _ in 0..3 {
		std::thread::sleep(std::time::Duration::from_millis(100));
		// Check that the coordinator is still running, presumably restarting
		// the child process
		assert!(!coordinator_handle.is_finished());
	}
}
