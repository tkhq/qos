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
	io::StreamPool,
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

// runs the enclave and app servers, waiting for manifest/pivot
// executed as a task from `Reaper::execute`
async fn run_server(
	server_state: Arc<RwLock<InterState>>,
	handles: Handles,
	nsm: Box<dyn NsmProvider + Send>,
	pool: StreamPool,
	app_pool: StreamPool,
	test_only_init_phase_override: Option<ProtocolPhase>,
) {
	let protocol_state =
		ProtocolState::new(nsm, handles.clone(), test_only_init_phase_override);
	// send a shared version of state and the async pool to each processor
	let processor =
		ProtocolProcessor::new(protocol_state.shared(), app_pool.shared());
	// listen_all will multiplex the processor accross all sockets
	let mut server = SocketServer::listen_all(pool, &processor)
		.expect("unable to get listen task list");

	loop {
		// see if we got interrupted
		if *server_state.read().unwrap() == InterState::Quitting {
			return;
		}

		let (manifest_present, pool_size) =
			get_pool_size_from_pivot_args(&handles);

		if manifest_present {
			let pool_size = pool_size.unwrap_or(1);
			// expand server to pool_size
			server
				.listen_to(pool_size, &processor)
				.expect("unable to listen_to on the running server");
			// expand app connections to pool_size
			processor
				.write()
				.await
				.expand_to(pool_size)
				.await
				.expect("unable to expand_to on the processor app pool");

			*server_state.write().unwrap() = InterState::PivotReady;
			eprintln!("Reaper::server manifest is present, breaking out of server check loop");
			break;
		}

		tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
	}

	eprintln!("Reaper::server post-expansion, waiting for shutdown");
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
		pool: StreamPool,
		app_pool: StreamPool,
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
			pool,
			app_pool,
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
				&& server_state == InterState::PivotReady
			{
				// The state required to pivot exists, so we can break this
				// holding pattern and start the pivot.
				break;
			}

			eprintln!("Reaper::execute waiting for pivot and manifest");
			tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
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
	// We've booted and pivot is ready
	PivotReady,
	// We're quitting (ctrl+c for tests and such)
	Quitting,
}

// return if we have manifest and get pool_size args if present from it
fn get_pool_size_from_pivot_args(handles: &Handles) -> (bool, Option<u32>) {
	if let Ok(envelope) = handles.get_manifest_envelope() {
		(true, extract_pool_size_arg(&envelope.manifest.pivot.args))
	} else {
		(false, None)
	}
}

// find the u32 value of --pool-size argument passed to the pivot if present
fn extract_pool_size_arg(args: &[String]) -> Option<u32> {
	if let Some((i, _)) =
		args.iter().enumerate().find(|(_, a)| *a == "--pool-size")
	{
		if let Some(pool_size_str) = args.get(i + 1) {
			pool_size_str.parse::<u32>().ok()
		} else {
			None
		}
	} else {
		None
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn extract_pool_size_arg_works() {
		// no arg
		assert_eq!(
			extract_pool_size_arg(&[
				"unrelated".to_owned(),
				"--args".to_owned()
			]),
			None
		);

		// should work
		assert_eq!(
			extract_pool_size_arg(&["--pool-size".to_owned(), "8".to_owned()]),
			Some(8)
		);

		// wrong number, expect None
		assert_eq!(
			extract_pool_size_arg(&["--pool-size".to_owned(), "8a".to_owned()]),
			None
		);

		// duplicate arg, use 1st
		assert_eq!(
			extract_pool_size_arg(&[
				"--pool-size".to_owned(),
				"8".to_owned(),
				"--pool-size".to_owned(),
				"9".to_owned()
			]),
			Some(8)
		);
	}
}

// See qos_test/tests/async_reaper for more tests
