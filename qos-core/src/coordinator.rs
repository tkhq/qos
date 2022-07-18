//! The coordinator is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::process::Command;

use crate::{
	handles::Handles,
	io::SocketAddress,
	protocol::{
		attestor::NsmProvider,
		services::boot::{PivotConfig, RestartPolicy},
		Executor,
	},
	server::SocketServer,
};

/// Primary entry point for running the enclave. Coordinates spawning the server
/// and pivot binary.
pub struct Coordinator;
impl Coordinator {
	/// Run the coordinator.
	///
	/// # Panics
	///
	/// - If spawning the pivot errors.
	/// - If waiting for the pivot errors.
	pub fn execute(
		handles: &Handles,
		nsm: Box<dyn NsmProvider + Send>,
		addr: SocketAddress,
		app_addr: SocketAddress,
	) {
		let handles2 = handles.clone();
		std::thread::spawn(move || {
			let executor = Executor::new(nsm, handles2, app_addr);
			SocketServer::listen(addr, executor).unwrap();
		});

		loop {
			if handles.quorum_key_exists()
				&& handles.pivot_exists()
				&& handles.manifest_envelope_exists()
			{
				// The state required to pivot exists, so we can break this
				// holding pattern and start the pivot.
				break;
			}

			std::thread::sleep(std::time::Duration::from_secs(1));
		}

		let PivotConfig { args, restart, .. } = handles
			.get_manifest_envelope()
			.expect("Checked above that the manifest exists.")
			.manifest
			.pivot;

		let mut pivot = Command::new(handles.pivot_path());
		pivot.args(&args[..]);
		match restart {
			RestartPolicy::Always => loop {
				let status = pivot
					.spawn()
					.expect("Failed to spawn")
					.wait()
					.expect("Pivot executable never started...");

				println!("Pivot exited with status: {}", status);
				println!("Restarting pivot ...");
			},
			RestartPolicy::Never => {
				let status = pivot
					.spawn()
					.expect("Failed to spawn")
					.wait()
					.expect("Pivot executable never started...");
				println!("Pivot exited with status: {}", status);
			}
		}

		println!("Coordinator exiting ...");
	}
}

// See qos-test/tests/coordinator for tests
