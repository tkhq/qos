//! The Reaper is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::process::Command;

use qos_nsm::NsmProvider;

use crate::{
	handles::Handles,
	io::SocketAddress,
	protocol::{
		services::boot::{PivotConfig, RestartPolicy},
		Processor, ProtocolPhase,
	},
	server::SocketServer,
};

const REAPER_RESTART_DELAY_IN_SECONDS : u64 = 1;

/// Primary entry point for running the enclave. Coordinates spawning the server
/// and pivot binary.
pub struct Reaper;
impl Reaper {
	/// Run the Reaper.
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
		test_only_init_phase_override: Option<ProtocolPhase>,
	) {
		let handles2 = handles.clone();
		std::thread::spawn(move || {
			let processor = Processor::new(
				nsm,
				handles2,
				app_addr,
				test_only_init_phase_override,
			);
			SocketServer::listen(addr, processor).unwrap();
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

		println!("Reaper::execute about to spawn pivot");

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

				println!("Pivot exited with status: {status}");

				// pause to ensure OS has enough time to clean up resources
				// before restarting
				std::thread::sleep(std::time::Duration::from_secs(REAPER_RESTART_DELAY_IN_SECONDS));

				println!("Restarting pivot ...");
			},
			RestartPolicy::Never => {
				let status = pivot
					.spawn()
					.expect("Failed to spawn")
					.wait()
					.expect("Pivot executable never started...");
				println!("Pivot exited with status: {status}");
			}
		}

		println!("Reaper exiting ...");
	}
}

// See qos_test/tests/reaper for tests
