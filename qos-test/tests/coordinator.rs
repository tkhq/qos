use std::fs::File;

use qos_core::coordinator::Coordinator;

const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";

#[test]
fn coordinator_e2e() {}

#[test]
fn coordinator_works() {
	let secret_path =
		"./coordinator_exits_cleanly_with_non_panicking_executable.secret";
	// For our sanity, ensure the secret does not yet exist. (Errors if file
	// doesn't exist)
	let _ = std::fs::remove_file(secret_path);
	assert!(File::open(PIVOT_OK_PATH).is_ok(),);

	let opts = [
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

	// Make the sure the coordinator executed successfully.
	coordinator_handle.join().unwrap();

	// Clean up
	std::fs::remove_file(secret_path).unwrap();
}

#[test]
fn coordinator_handles_non_zero_exits() {
	let secret_path =
		"./coordinator_keeps_re_spawning_pivot_executable_that_panics.secret";
	// For our sanity, ensure the secret does not yet exist. (Errors if file
	// doesn't exist)
	let _ = std::fs::remove_file(secret_path);
	assert!(File::open(PIVOT_ABORT_PATH).is_ok(),);

	let opts = [
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

	let opts = [
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
