//! The Reaper is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::{
	net::{Ipv4Addr, SocketAddr, SocketAddrV4},
	process::Stdio,
	sync::{Arc, RwLock},
	time::Duration,
};

use qos_nsm::NsmProvider;
use tokio::{
	io::{AsyncBufReadExt, BufReader},
	process::{Child, Command},
};

use crate::{
	handles::Handles,
	io::{HostBridge, IOError, SocketAddress, StreamPool},
	protocol::{
		ProtocolPhase, ProtocolState,
		msg::WorkloadStatus,
		processor::ProtocolProcessor,
		services::boot::{BridgeConfig, RestartPolicy},
	},
	server::SocketServer,
};

/// Delay for restarting the pivot app if the process exits.
pub const REAPER_RESTART_DELAY: Duration = Duration::from_millis(50);
/// Delay until the reaper exits after pivot app with a Never restart policy
/// exits.
pub const REAPER_EXIT_DELAY: Duration = Duration::from_secs(3);

const REAPER_STATE_CHECK_DELAY: Duration = Duration::from_millis(100);

// runs the enclave vsock setup server for qos_host communication, waiting for manifest/pivot
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
		SocketServer::listen_all(core_pool, protocol_processor, 1)
			.expect("unable to get listen task list for protocol server");

	println!("Reaper::server running");
	while *server_state.read().unwrap() != InterState::Quitting {
		tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
	}

	println!("Reaper::server shutdown");
}

// runs the VSOCK -> TCP bridge so that apps can use any TCP based protocol without worrying about VSOCK
// communication. This is started if `PivotConfig::bridge_config` has any members defined.
// uses the enclave core socket and given pivot host port to constuct the VSOCK to TCP bridge.
fn run_vsock_to_tcp_bridge(
	core_socket: &SocketAddress,
	bridges: &Vec<BridgeConfig>,
) -> Result<(), IOError> {
	// do nothing if we're not asked to provide bridging
	if bridges.is_empty() {
		println!("skipping host bridge, not configured");
		return Ok(());
	}

	for bc in bridges {
		match bc {
			BridgeConfig::Server { port, host: _ } => {
				let app_socket = core_socket.with_port(*port)?;
				let host_addr: SocketAddr =
					SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port).into();
				let app_pool = StreamPool::single(app_socket)?;
				let bridge = HostBridge::new(app_pool, host_addr);

				bridge.vsock_to_tcp();
			}
			BridgeConfig::Client { port: _, host: _ } => {
				panic!("client bridge unimplemented")
			} // TODO: implement
		}
	}

	Ok(())
}

fn reprint_pivot_output(child: &mut Child) {
	let stdout = child.stdout.take().expect("failed to get pivot stdout");
	let stderr = child.stderr.take().expect("failed to get pivot stderr");

	let stdout_reader = BufReader::new(stdout);
	let stderr_reader = BufReader::new(stderr);

	tokio::spawn(async move {
		let mut stdout_lines = stdout_reader.lines();
		let mut stderr_lines = stderr_reader.lines();

		loop {
			tokio::select! {
				line = stdout_lines.next_line() => {
					match line {
						Ok(Some(line)) => println!("PIVOT[OUT]: {line}"),
						Ok(None) => break, // process exit
						Err(e) => eprintln!("error reading pivot stdout: {e}"),
					}
				}
				line = stderr_lines.next_line() => {
					match line {
						Ok(Some(line)) => eprintln!("PIVOT[ERR]: {line}"),
						Ok(None) => break, // process exit
						Err(e) => eprintln!("error reading pivot stderr: {e}"),
					}
				}
			}
		}
	});
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
			core_socket.clone(),
			test_only_init_phase_override,
		));

		loop {
			let server_state = *inter_state.read().unwrap();
			// helper for integration tests and manual runs aka qos_core binary
			if server_state == InterState::Quitting {
				eprintln!("quit called by ctrl+c");
				std::process::exit(1);
			}

			if handles.quorum_key_exists() && handles.manifest_envelope_exists()
			{
				let manifest = handles
					.get_manifest_envelope()
					.expect("Checked above that the manifest exists.")
					.manifest();
				if manifest.is_oci_image()
					|| (manifest.is_binary_pivot() && handles.pivot_exists())
				{
					// The state required to pivot exists, so we can break this
					// holding pattern and start the workload.
					break;
				}
			}

			eprintln!("Reaper::execute waiting for workload and manifest");
			tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
		}

		println!("Reaper::execute about to spawn workload");

		let manifest = handles
			.get_manifest_envelope()
			.expect("Checked above that the manifest exists.")
			.manifest();
		if let Some(oci_image) = manifest.oci_image() {
			run_vsock_to_tcp_bridge(&core_socket, &oci_image.bridge_config)
				.expect("failed to run OCI VSOCK/TCP bridge");
			let verified =
				crate::protocol::services::boot::oci::inspect_stored_oci_image(
					handles, oci_image,
				)
				.expect("failed to inspect OCI image");
			let bundle =
				crate::protocol::services::boot::oci::prepare_oci_runtime_bundle(
					handles, oci_image,
				)
				.expect("failed to prepare OCI runtime bundle");
			let mut workload_status = WorkloadStatus {
				kind: "ociImage".to_string(),
				digest: Some(oci_image.digest.as_str().to_string()),
				resolved: true,
				unpacked: true,
				running: false,
				exposed_ports: verified.exposed_ports,
				volumes: verified.volumes,
				last_exit_status: None,
				last_error: None,
			};
			if let Err(err) = handles.put_workload_status(&workload_status) {
				eprintln!("failed to write OCI workload status: {err}");
			}
			let restart = manifest.restart();
			let debug = manifest.debug_mode();
			let bundle_dir = bundle.bundle_dir.clone();
			let state_root = bundle_dir.join("state");

			loop {
				workload_status.running = true;
				workload_status.last_error = None;
				if let Err(err) = handles.put_workload_status(&workload_status)
				{
					eprintln!("failed to write OCI workload status: {err}");
				}
				let run_bundle = bundle_dir.clone();
				let run_state = state_root.clone();
				let result = tokio::task::spawn_blocking(move || {
					crate::oci_runtime::run(
						&run_bundle,
						&run_state,
						"qos-workload",
						debug,
					)
				})
				.await
				.expect("libcontainer worker panicked");
				let exit_code = match result {
					Ok(code) => code,
					Err(error) => {
						eprintln!("OCI workload failed: {error}");
						workload_status.last_error = Some(error);
						1
					}
				};

				println!("OCI workload exited with status: {exit_code}");
				workload_status.running = false;
				workload_status.last_exit_status = Some(exit_code);
				if let Err(err) = handles.put_workload_status(&workload_status)
				{
					eprintln!("failed to write OCI workload status: {err}");
				}
				if restart == RestartPolicy::Never {
					tokio::time::sleep(REAPER_EXIT_DELAY).await;
					break;
				}
				tokio::time::sleep(REAPER_RESTART_DELAY).await;
			}
			*inter_state.write().unwrap() = InterState::Quitting;
			server_worker.abort();
			return;
		}
		let args = manifest.args().to_vec();
		let restart = manifest.restart();
		let host_config = manifest.bridge_config().to_vec();

		// if the app indicates the need for the VSOCK -> TCP bridge, run it as another task
		run_vsock_to_tcp_bridge(&core_socket, &host_config)
			.expect("failed to run VSOCK -> TCP socket bridge");

		let mut pivot = Command::new(handles.pivot_path());
		pivot.env_clear();
		pivot.args(&args[..]);
		// Only pipe pivot output when it will be drained below.
		if manifest.debug_mode() {
			pivot.stdout(Stdio::piped()).stderr(Stdio::piped());
		} else {
			pivot.stdout(Stdio::null()).stderr(Stdio::null());
		}

		let mut workload_status = WorkloadStatus {
			kind: "binaryPivot".to_string(),
			digest: None,
			resolved: true,
			unpacked: false,
			running: false,
			exposed_ports: vec![],
			volumes: vec![],
			last_exit_status: None,
			last_error: None,
		};
		if let Err(err) = handles.put_workload_status(&workload_status) {
			eprintln!("failed to write pivot workload status: {err}");
		}

		loop {
			workload_status.running = true;
			workload_status.last_error = None;
			if let Err(err) = handles.put_workload_status(&workload_status) {
				eprintln!("failed to write pivot workload status: {err}");
			}
			let mut child = pivot.spawn().expect("Failed to spawn pivot");
			// print pivot stderr and stdout if in debug mode
			// *NOTE*: this requires `DEBUG` and `LOGS` env vars set when booting the enclave itself. If not, nothing will be visible
			if manifest.debug_mode() {
				reprint_pivot_output(&mut child);
			}

			let status =
				child.wait().await.expect("Pivot executable never started...");

			println!("Pivot exited with status: {status}");
			workload_status.running = false;
			workload_status.last_exit_status = status.code();
			if let Err(err) = handles.put_workload_status(&workload_status) {
				eprintln!("failed to write pivot workload status: {err}");
			}
			// pause to ensure OS has enough time to clean up resources
			// before restarting
			tokio::time::sleep(REAPER_RESTART_DELAY).await;

			match restart {
				RestartPolicy::Always => {}
				RestartPolicy::Never => break,
			}
			println!("Restarting pivot ...");
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
