//! The coordinator is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::{fs::File, process::Command};

use crate::{cli::EnclaveOptions, protocol::Executor, server::SocketServer};

// TODO: should this be renamed to drive?
pub struct Coordinator;
impl Coordinator {
	/// Run the coordinator.
	/// TODO: make the pivot and secret file paths injectable
	pub fn execute(opts: EnclaveOptions) {
		let secret_file = opts.secret_file();
		let pivot_file = opts.pivot_file();

		std::thread::spawn(move || {
			let executor = Executor::new(
				opts.nsm(),
				opts.secret_file(),
				opts.pivot_file(),
			);
			SocketServer::listen(opts.addr(), executor).unwrap();
		});

		// Check if the enclaves secret and the pivot executable is loaded.
		loop {
			let secret_file_exists = is_file(&secret_file);
			let pivot_file_exists = is_file(&pivot_file);

			if secret_file_exists && pivot_file_exists {
				break
			}

			std::thread::sleep(std::time::Duration::from_secs(1));
		}

		// "Pivot" to the executable by spawning a child process running the
		// executable.
		let mut pivot = Command::new(pivot_file);
		let mut child_process =
			pivot.spawn().expect("Process failed to execute...");

		// Child process restart logic
		loop {
			match child_process.wait() {
				Ok(status) => {
					println!("Pivot executable exited with {}", status);
					break
				} // TODO: should we break here?
				Err(status) => {
					println!("Pivot executable error-ed with {}", status);
					println!("Re-spawning pivot executable child process ...");
					child_process =
						pivot.spawn().expect("Process failed to execute...");
					continue
				}
			}
		}
	}
}

fn is_file(path: &str) -> bool {
	match File::open(path) {
		Ok(file) => {
			if let Ok(metadata) = file.metadata() {
				return metadata.len() > 0
			} else {
				return false
			}
		}
		Err(_) => return false,
	}
}

#[cfg(test)]
mod test {
	use super::*;

	const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";

	#[test]
	fn coordinator_exits_cleanly_with_non_panicking_executable() {
		let cec_secret_path = "./cec_test.secret";
		// For our sanity, ensure the secret does not yet exist. (Errors if file
		// doesn't exist)
		let _ = std::fs::remove_file(cec_secret_path);

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
		std::fs::write(cec_secret_path, b"super dank tank secret tech")
			.unwrap();

		// Make the sure the coordinator executed successfully.
		coordinator_handle.join().unwrap();

		// Clean up
		std::fs::remove_file(cec_secret_path).unwrap();
	}
}
