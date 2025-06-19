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

/// Delay for restarting the pivot app if the process exits.
pub const REAPER_RESTART_DELAY_IN_SECONDS: u64 = 1;
/// Delay until the reaper exits after pivot app with a Never restart policy
/// exits.
pub const REAPER_EXIT_DELAY_IN_SECONDS: u64 = 3;

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
	#[allow(dead_code)]
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
				std::thread::sleep(std::time::Duration::from_secs(
					REAPER_RESTART_DELAY_IN_SECONDS,
				));

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

		std::thread::sleep(std::time::Duration::from_secs(
			REAPER_EXIT_DELAY_IN_SECONDS,
		));
		println!("Reaper exiting ... ");
	}
}

#[cfg(feature = "async")]
mod inner {
	use std::sync::Arc;
	use tokio::sync::RwLock;

	#[allow(clippy::wildcard_imports)]
	use super::*;
	use crate::{
		async_server::AsyncSocketServer,
		io::AsyncStreamPool,
		protocol::{async_processor::AsyncProcessor, ProtocolState},
	};

	impl Reaper {
		/// Run the Reaper in an async way using Tokio runtime.
		///
		/// # Panics
		///
		/// - If spawning the pivot errors.
		/// - If waiting for the pivot errors.
		#[allow(dead_code)]
		pub async fn async_execute(
			handles: &Handles,
			nsm: Box<dyn NsmProvider + Send>,
			pool: AsyncStreamPool,
			app_pool: AsyncStreamPool,
			test_only_init_phase_override: Option<ProtocolPhase>,
		) {
			let handles2 = handles.clone();
			let quit = Arc::new(RwLock::new(false));
			let inner_quit = quit.clone();

			tokio::spawn(async move {
				// create the state
				let protocol_state = ProtocolState::new(
					nsm,
					handles2,
					test_only_init_phase_override,
				);
				// send a shared version of state and the async pool to each processor
				let processor = AsyncProcessor::new(
					protocol_state.shared(),
					app_pool.shared(),
				);
				// listen_all will multiplex the processor accross all sockets
				let tasks = AsyncSocketServer::listen_all(pool, &processor)
					.expect("unable to get listen task list");

				match tokio::signal::ctrl_c().await {
					Ok(()) => {
						eprintln!("handling ctrl+c the tokio way");
						for task in tasks {
							task.abort();
						}
						*inner_quit.write().await = true;
					}
					Err(err) => panic!("{err}"),
				}
			});

			loop {
				if *quit.read().await == true {
					eprintln!("quit called by ctrl+c");
					std::process::exit(1);
				}

				if handles.quorum_key_exists()
					&& handles.pivot_exists()
					&& handles.manifest_envelope_exists()
				{
					// The state required to pivot exists, so we can break this
					// holding pattern and start the pivot.
					break;
				}

				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
					tokio::time::sleep(std::time::Duration::from_secs(
						REAPER_RESTART_DELAY_IN_SECONDS,
					))
					.await;

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

			tokio::time::sleep(std::time::Duration::from_secs(
				REAPER_EXIT_DELAY_IN_SECONDS,
			))
			.await;
			println!("Reaper exiting ... ");
		}
	}
}

// See qos_test/tests/reaper for tests
