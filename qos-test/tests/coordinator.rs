use std::fs::File;

use qos_core::coordinator::Coordinator;

const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";

#[test]
fn coordinator_exits_cleanly_with_non_panicking_executable() {
	let cec_secret_path = "./cec_test.secret";
	// For our sanity, ensure the secret does not yet exist. (Errors if file
	// doesn't exist)
	let _ = std::fs::remove_file(cec_secret_path);
	assert!(
			File::open(PIVOT_OK_PATH).is_ok(),
			"Make sure the pivot-test-bin crate has been compiled. Running `cargo build` from the workspace root should fix this."
		);

	let opts = [
		"--usock",
		"./cec_test.sock",
		"--mock",
		"true",
		"--secret-file",
		cec_secret_path,
		"--pivot-file",
		PIVOT_OK_PATH,
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
	std::fs::write(cec_secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the coordinator executed successfully.
	coordinator_handle.join().unwrap();

	// Clean up
	std::fs::remove_file(cec_secret_path).unwrap();
}
