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
	use std::{
		sync::{Arc, RwLock},
		time::Duration,
	};

	#[allow(clippy::wildcard_imports)]
	use super::*;
	use crate::{
		async_server::AsyncSocketServer,
		io::AsyncStreamPool,
		protocol::{async_processor::AsyncProcessor, ProtocolState},
	};

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

	impl Reaper {
		/// Run the Reaper using Tokio inside a thread for server processing.
		///
		/// # Panics
		///
		/// - If spawning the pivot errors.
		/// - If waiting for the pivot errors.
		#[allow(dead_code)]
		#[allow(clippy::too_many_lines)]
		pub fn async_execute(
			handles: &Handles,
			nsm: Box<dyn NsmProvider + Send>,
			pool: AsyncStreamPool,
			app_pool: AsyncStreamPool,
			test_only_init_phase_override: Option<ProtocolPhase>,
		) {
			let handles2 = handles.clone();
			let inter_state = Arc::new(RwLock::new(InterState::Booting));
			let server_state = inter_state.clone();

			std::thread::spawn(move || {
				tokio::runtime::Builder::new_current_thread()
					.enable_all()
					.build()
					.unwrap()
					.block_on(async move {
						// run the state processor inside a tokio runtime in this thread
						// create the state
						let protocol_state = ProtocolState::new(
							nsm,
							handles2.clone(),
							test_only_init_phase_override,
						);
						// send a shared version of state and the async pool to each processor
						let mut processor = AsyncProcessor::new(
							protocol_state.shared(),
							app_pool.shared(),
						);
						// listen_all will multiplex the processor accross all sockets
						let mut server =
							AsyncSocketServer::listen_all(pool, &processor)
								.expect("unable to get listen task list");

						loop {
							let (manifest_present, pool_size) =
								get_pool_size_from_pivot_args(&handles2);
							let pool_size = pool_size.unwrap_or(1);
							// expand server to pool_size + 1 (due to qos-host extra socket)
							server.listen_to(pool_size + 1, &processor).expect(
								"unable to listen_to on the running server",
							);
							// expand app connections to pool_size
							processor.expand_to(pool_size).await.expect(
								"unable to expand_to on the processor app pool",
							);

							if manifest_present {
								*server_state.write().unwrap() =
									InterState::PivotReady;
								eprintln!("manifest is present, breaking out of server check loop");
								break;
							}

							// sleep up to 1s, checking for ctrl+c, if it happens break out
							if let Ok(ctrl_res) = tokio::time::timeout(
								Duration::from_secs(1),
								tokio::signal::ctrl_c(),
							)
							.await
							{
								return ctrl_c_handler(
									ctrl_res,
									server,
									&server_state,
								);
							}
						}
						// wait until ctrl+c
						ctrl_c_handler(
							tokio::signal::ctrl_c().await,
							server,
							&server_state,
						);
					});
			});

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

				eprintln!("Reaper looping");
				std::thread::sleep(std::time::Duration::from_secs(1));
				eprintln!("Reaper done looping");
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

	fn ctrl_c_handler(
		ctrl_c: std::io::Result<()>,
		server: AsyncSocketServer,
		server_state: &Arc<RwLock<InterState>>,
	) {
		match ctrl_c {
			Ok(()) => {
				server.terminate();
				*server_state.write().unwrap() = InterState::Quitting;
			}
			Err(err) => panic!("{err}"),
		}
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
				match pool_size_str.parse::<u32>() {
					Ok(pool_size) => Some(pool_size),
					Err(_) => None,
				}
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
				extract_pool_size_arg(&vec![
					"unrelated".to_owned(),
					"--args".to_owned(),
				]),
				None
			);

			// should work
			assert_eq!(
				extract_pool_size_arg(&vec![
					"--pool-size".to_owned(),
					"8".to_owned(),
				]),
				Some(8)
			);

			// wrong number, expect None
			assert_eq!(
				extract_pool_size_arg(&vec![
					"--pool-size".to_owned(),
					"8a".to_owned(),
				]),
				None
			);

			// duplicate arg, use 1st
			assert_eq!(
				extract_pool_size_arg(&vec![
					"--pool-size".to_owned(),
					"8".to_owned(),
					"--pool-size".to_owned(),
					"9".to_owned(),
				]),
				Some(8)
			);
		}
	}
}

// See qos_test/tests/async_reaper for more tests
