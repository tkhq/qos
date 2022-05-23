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
			if is_file(&secret_file) && is_file(&pivot_file) {
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
				Ok(_) => {
					println!("Child process exited with no error")
				} // TODO: should we break here?
				Err(_) => {
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
