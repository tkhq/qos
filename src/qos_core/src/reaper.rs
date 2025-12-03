//! The Reaper is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::{
	sync::{Arc, RwLock},
	time::Duration,
};

use qos_nsm::NsmProvider;
use tokio::process::Command;

use crate::{
	handles::Handles,
	io::{SocketAddress, StreamPool},
	protocol::{
		processor::ProtocolProcessor,
		services::boot::{PivotConfig, RestartPolicy},
		ProtocolPhase, ProtocolState,
	},
	server::SocketServer,
};

/// Delay for restarting the pivot app if the process exits.
pub const REAPER_RESTART_DELAY: Duration = Duration::from_millis(50);
/// Delay until the reaper exits after pivot app with a Never restart policy
/// exits.
pub const REAPER_EXIT_DELAY: Duration = Duration::from_secs(3);

const REAPER_STATE_CHECK_DELAY: Duration = Duration::from_millis(100);
const DEFAULT_POOL_SIZE: u8 = 1;

// runs the enclave and app servers, waiting for manifest/pivot
// executed as a task from `Reaper::execute`
async fn run_server(
	server_state: Arc<RwLock<InterState>>,
	handles: Handles,
	nsm: Box<dyn NsmProvider + Send>,
	core_socket: SocketAddress,
	test_only_init_phase_override: Option<ProtocolPhase>,
) {
	let protocol_state =
		ProtocolState::new(nsm, handles.clone(), test_only_init_phase_override)
			.shared();
	let core_pool = StreamPool::single(core_socket)
		.expect("unable to create single socket core pool");
	// send a shared version of state and the async pool to each processor
	let protocol_processor = ProtocolProcessor::new(protocol_state);

	// listen on the protocol server
	let _protocol_server =
		SocketServer::listen_all(core_pool, &protocol_processor)
			.expect("unable to get listen task list for protocol server");

	eprintln!("Reaper::server running");
	while *server_state.read().unwrap() != InterState::Quitting {
		tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
	}

	eprintln!("Reaper::server shutdown");
}

/// Primary entry point for running the enclave. Coordinates spawning the server
/// and pivot binary.
pub struct Reaper;
impl Reaper {
	/// Run the Reaper, with the given shutdown oneshot channel Receiver. If a signal is passed (regardless of value)
	/// the Reaper will shut down and clean up the server. It is the responsibility of the caller to send the shutdown
	/// signal.
	///
	/// # Panics
	///
	/// - If spawning the pivot errors.
	/// - If waiting for the pivot errors.
	#[allow(dead_code)]
	pub async fn execute(
		handles: &Handles,
		nsm: Box<dyn NsmProvider + Send>,
		core_socket: SocketAddress,
		test_only_init_phase_override: Option<ProtocolPhase>,
	) {
		// state switch to communicate between pivot run task (here) and run_server task
		// we need to establish
		let inter_state = Arc::new(RwLock::new(InterState::Booting));
		let server_state = inter_state.clone();

		let server_worker = tokio::spawn(run_server(
			server_state,
			handles.clone(),
			nsm,
			core_socket,
			test_only_init_phase_override,
		));

		loop {
			let server_state = *inter_state.read().unwrap();
			// helper for integration tests and manual runs aka qos_core binary
			if server_state == InterState::Quitting {
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

			eprintln!("Reaper::execute waiting for pivot and manifest");
			tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
		}

		println!("Reaper::execute about to spawn pivot");

		let manifest = handles
			.get_manifest_envelope()
			.expect("Checked above that the manifest exists.")
			.manifest;
		let PivotConfig { args, restart, .. } = manifest.pivot;

		let mut pivot = Command::new(handles.pivot_path());
		// set the pool-size env var for pivots that use it
		pivot
			.env_clear()
			.env(
				"POOL_SIZE",
				manifest.pool_size.unwrap_or(DEFAULT_POOL_SIZE).to_string(),
			)
			.env("CID", "3"); // TODO: ales channels
		pivot.args(&args[..]);
		match restart {
			RestartPolicy::Always => loop {
				let status = pivot
					.spawn()
					.expect("Failed to spawn")
					.wait()
					.await
					.expect("Pivot executable never started...");

				println!("Pivot exited with status: {status}");

				// pause to ensure OS has enough time to clean up resources
				// before restarting
				tokio::time::sleep(REAPER_RESTART_DELAY).await;

				println!("Restarting pivot ...");
			},
			RestartPolicy::Never => {
				let status = pivot
					.spawn()
					.expect("Failed to spawn")
					.wait()
					.await
					.expect("Pivot executable never started...");
				println!("Pivot (no restart) exited with status: {status}");
			}
		}

		*inter_state.write().unwrap() = InterState::Quitting;

		tokio::time::sleep(REAPER_EXIT_DELAY).await;

		if let Err(err) = server_worker.await {
			eprintln!("Reaper::execute server_worker join error: {err:?}");
		}

		println!("Reaper exiting ... ");
	}
}

// basic helper for x-thread comms in Reaper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterState {
	// We're booting, no pivot yet
	Booting,
	// We're quitting (ctrl+c for tests and such)
	Quitting,
}

// See qos_test/tests/async_reaper for more tests
