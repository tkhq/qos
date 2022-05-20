use std::fs::File;
use std::process::Command;

use crate::cli::EnclaveOptions;
use crate::{protocol::Executor, server::SocketServer};
use crate::{PIVOT_FILE, SECRET_FILE};

pub struct Coordinator;
impl Coordinator {
	pub fn execute(options: EnclaveOptions) {
		std::thread::spawn(move || {
			let addr = options.addr();
			let nsm = options.nsm();
			let executor = Executor::new(nsm);
			SocketServer::listen(addr, executor).unwrap();
		});

		// TODO: Reaper

		loop {
			if is_secret_loaded() && is_pivot_loaded() {
				break;
			}

			std::thread::sleep(std::time::Duration::from_secs(1));
		}

		let mut pivot = Command::new(PIVOT_FILE);
		let mut handle = pivot.spawn().expect("Process failed to execute...");

		// restart loop
		loop {
			match handle.wait() {
				Ok(_) => {}
				Err(_) => {
					handle =
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
