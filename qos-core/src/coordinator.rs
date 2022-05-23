//! The coordinator is responsible for initializing the enclave processes. Concretely it spawns
//! the enclave server and launches the "pivot" executable once it becomes available in the file
//! system.
use std::fs::File;
use std::process::Command;

use crate::cli::EnclaveOptions;
use crate::{protocol::Executor, server::SocketServer};
use crate::{PIVOT_FILE, SECRET_FILE};

// TODO: should this be renamed to drive?
pub struct Coordinator;
impl Coordinator {
	/// Run the coordinator.
	pub fn execute(options: EnclaveOptions) {
		std::thread::spawn(move || {
			let addr = options.addr();
			let nsm = options.nsm();
			let executor = Executor::new(nsm);
			SocketServer::listen(addr, executor).unwrap();
		});

		loop {
			if is_secret_loaded() && is_pivot_loaded() {
				break;
			}

			std::thread::sleep(std::time::Duration::from_secs(1));
		}

		// "Pivot" to the executable by spawning a child process running the executable.
		let mut pivot = Command::new(PIVOT_FILE);
		let mut child_process = pivot.spawn().expect("Process failed to execute...");

		// Child process restart logic
		loop {
			match child_process.wait() {
				Ok(_) => { println!("Child process exited with no error")}, // TODO: should we break here?
				Err(_) => {
					child_process =
						pivot.spawn().expect("Process failed to execute...");
					continue;
				}
			}
		}
	}
}

fn is_secret_loaded() -> bool {
	is_file(SECRET_FILE)
}

fn is_pivot_loaded() -> bool {
	is_file(PIVOT_FILE)
}

fn is_file(path: &str) -> bool {
	match File::open(path) {
		Ok(file) => {
			if let Ok(metadata) = file.metadata() {
				return metadata.len() > 0;
			} else {
				return false;
			}
		}
		Err(_) => return false,
	}
}
