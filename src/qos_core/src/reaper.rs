//! The Reaper is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::{
	collections::BTreeMap,
	fs,
	net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
	process::Stdio,
	sync::{
		Arc, RwLock,
		atomic::{AtomicBool, Ordering},
	},
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
		oci_status::{OciWorkloadStatus, SharedOciStatus},
		processor::ProtocolProcessor,
		services::boot::{BridgeConfig, RestartPolicy},
		services::boot::{ManifestV3, VersionedManifest},
	},
	server::SocketServer,
};

/// Delay for restarting the pivot app if the process exits.
pub const REAPER_RESTART_DELAY: Duration = Duration::from_millis(50);
/// Delay until the reaper exits after pivot app with a Never restart policy
/// exits.
pub const REAPER_EXIT_DELAY: Duration = Duration::from_secs(3);
const OCI_STATUS_EXIT_DELAY: Duration = Duration::from_secs(10);
const CORE_MAX_CONNECTIONS: usize = 4;

const REAPER_STATE_CHECK_DELAY: Duration = Duration::from_millis(100);
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

// runs the enclave vsock setup server for qos_host communication, waiting for manifest/pivot
// executed as a task from `Reaper::execute`
async fn run_server(
	server_state: Arc<RwLock<InterState>>,
	handles: Handles,
	nsm: Box<dyn NsmProvider + Send>,
	core_socket: SocketAddress,
	test_only_init_phase_override: Option<ProtocolPhase>,
	oci_status: SharedOciStatus,
) {
	let protocol_state = ProtocolState::new_with_oci_status(
		nsm,
		handles.clone(),
		test_only_init_phase_override,
		oci_status,
	)
	.shared();
	let core_pool = StreamPool::single(core_socket)
		.expect("unable to create single socket core pool");
	// send a shared version of state and the async pool to each processor
	let protocol_processor = ProtocolProcessor::new(protocol_state);

	// listen on the protocol server
	let _protocol_server = SocketServer::listen_all(
		core_pool,
		protocol_processor,
		CORE_MAX_CONNECTIONS,
	)
	.expect("unable to get listen task list for protocol server");

	println!("Reaper::server running");
	while *server_state.read().unwrap() != InterState::Quitting {
		tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
	}

	println!("Reaper::server shutdown");
}

async fn run_oci_workload_group(
	handles: &Handles,
	manifest: ManifestV3,
	status: &SharedOciStatus,
) {
	status.write().unwrap().extend(manifest.workloads.iter().map(|workload| {
		let name = workload.name().clone();
		(
			name.clone(),
			OciWorkloadStatus::pending(name, workload.image().digest().clone()),
		)
	}));
	println!("Reaper::execute about to start OCI workloads");
	let handles = handles.clone();
	let status = Arc::clone(status);
	let shutdown = Arc::new(AtomicBool::new(false));
	let worker_shutdown = Arc::clone(&shutdown);
	let mut worker = tokio::task::spawn_blocking(move || {
		#[cfg(target_os = "linux")]
		{
			crate::oci_manager::run_oci_workloads(
				&handles,
				&manifest,
				&status,
				&worker_shutdown,
			)
			.map_err(|error| error.to_string())
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (handles, manifest, status, worker_shutdown);
			Err("OCI workloads require Linux".to_owned())
		}
	});
	let result = tokio::select! {
		result = &mut worker => result,
		() = oci_shutdown_signal() => {
			shutdown.store(true, Ordering::Release);
			worker.await
		}
	};
	match result {
		Ok(Ok(())) => println!("all OCI workloads stopped"),
		Ok(Err(error)) => eprintln!("OCI workload group failed: {error}"),
		Err(error) => eprintln!("OCI workload monitor join failed: {error}"),
	}
}

#[cfg(unix)]
async fn oci_shutdown_signal() {
	let mut terminate = tokio::signal::unix::signal(
		tokio::signal::unix::SignalKind::terminate(),
	)
	.expect("failed to install SIGTERM handler");
	tokio::select! {
		_ = tokio::signal::ctrl_c() => {}
		_ = terminate.recv() => {}
	}
}

#[cfg(not(unix))]
async fn oci_shutdown_signal() {
	let _ = tokio::signal::ctrl_c().await;
}

// runs configured bridges based on `BridgeConfig` so that apps can use any TCP based protocol without worrying about VSOCK
// communication. This is started if `PivotConfig::bridge_config` has any members defined.
// uses the enclave core socket and given pivot host port to construct the VSOCK to TCP bridge for server side
// and opens a fully transparent egress if client side is set.
fn run_bridges(
	core_socket: &SocketAddress,
	bridges: &[BridgeConfig],
) -> Result<(), IOError> {
	// do nothing if we're not asked to provide bridging
	if bridges.is_empty() {
		println!("skipping host bridge, not configured");
		return Ok(());
	}

	let mut egress_enabled = false;

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
				// only run one instance as it covers ALL ports, the others are for firewalls
				if !egress_enabled {
					egress_enabled = true;
					run_egress_bridge(core_socket);
				}
			}
		}
	}

	Ok(())
}

// dummy placeholder
#[cfg(not(feature = "egress"))]
fn run_egress_bridge(_core_socket: &SocketAddress) {
	panic!("unable to run egress without vsock support");
}

// run the transparent host egress
#[cfg(feature = "egress")]
fn run_egress_bridge(core_socket: &SocketAddress) {
	let cid = core_socket.vsock().cid();

	crate::egress::run_looping(
		"/egress",
		&format!("--cid {cid} --vsock-to-host false"),
	);
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

fn resolv_conf_with_nameservers(resolvers: &[IpAddr]) -> String {
	let mut output = String::new();
	for resolver in resolvers {
		output.push_str("nameserver ");
		output.push_str(&resolver.to_string());
		output.push('\n');
	}
	output
}

fn write_resolv_conf(resolvers: &[IpAddr]) -> std::io::Result<()> {
	fs::write(RESOLV_CONF_PATH, resolv_conf_with_nameservers(resolvers))
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
		let oci_status: SharedOciStatus =
			Arc::new(RwLock::new(BTreeMap::new()));

		let server_worker = tokio::spawn(run_server(
			server_state,
			handles.clone(),
			nsm,
			core_socket.clone(),
			test_only_init_phase_override,
			Arc::clone(&oci_status),
		));

		loop {
			let server_state = *inter_state.read().unwrap();
			// helper for integration tests and manual runs aka qos_core binary
			if server_state == InterState::Quitting {
				eprintln!("quit called by ctrl+c");
				std::process::exit(1);
			}

			let ready = handles.quorum_key_exists()
				&& handles.manifest_envelope_exists()
				&& handles.get_manifest_envelope().is_ok_and(|envelope| {
					matches!(envelope.manifest(), VersionedManifest::V3(_))
						|| handles.pivot_exists()
				});
			if ready {
				// The state required to pivot exists, so we can break this
				// holding pattern and start the pivot.
				break;
			}

			eprintln!("Reaper::execute waiting for pivot and manifest");
			tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
		}

		let manifest = handles
			.get_manifest_envelope()
			.expect("Checked above that the manifest exists.")
			.manifest();
		if let VersionedManifest::V3(oci_manifest) = manifest {
			run_oci_workload_group(handles, oci_manifest, &oci_status).await;
			tokio::time::sleep(OCI_STATUS_EXIT_DELAY).await;
			*inter_state.write().unwrap() = InterState::Quitting;
			if let Err(error) = server_worker.await {
				eprintln!(
					"Reaper::execute server_worker join error: {error:?}"
				);
			}
			println!("Reaper exiting ... ");
			return;
		}

		println!("Reaper::execute about to spawn pivot");
		let (Some(args), Some(restart)) = (manifest.args(), manifest.restart())
		else {
			eprintln!("Manifest V3 requires the OCI runtime");
			server_worker.abort();
			return;
		};
		let args = args.to_vec();
		let host_config = manifest.bridge_config().to_vec();
		let dns_config = manifest.dns_config().cloned();

		if let Some(dns_config) = dns_config {
			write_resolv_conf(&dns_config.resolvers)
				.expect("failed to write /etc/resolv.conf");
		}

		// if the app indicates the need for the VSOCK -> TCP bridge, run it as another task
		run_bridges(&core_socket, &host_config)
			.expect("failed to run ingress/egress bridges");

		let mut pivot = Command::new(handles.pivot_path());
		pivot.env_clear();
		pivot.args(&args[..]);
		// Only pipe pivot output when it will be drained below.
		if manifest.debug_mode() {
			pivot.stdout(Stdio::piped()).stderr(Stdio::piped());
		} else {
			pivot.stdout(Stdio::null()).stderr(Stdio::null());
		}

		loop {
			let mut child = pivot.spawn().expect("Failed to spawn pivot");
			// print pivot stderr and stdout if in debug mode
			// *NOTE*: this requires `DEBUG` and `LOGS` env vars set when booting the enclave itself. If not, nothing will be visible
			if manifest.debug_mode() {
				reprint_pivot_output(&mut child);
			}

			let status =
				child.wait().await.expect("Pivot executable never started...");

			println!("Pivot exited with status: {status}");
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn resolv_conf_write_uses_configured_nameservers() {
		let resolvers = ["1.1.1.1", "2606:4700:4700::1111"]
			.into_iter()
			.map(|resolver| resolver.parse().unwrap())
			.collect::<Vec<IpAddr>>();

		assert_eq!(
			resolv_conf_with_nameservers(&resolvers),
			"nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
		);
	}

	#[test]
	fn resolv_conf_write_supports_empty_resolver_list() {
		assert_eq!(resolv_conf_with_nameservers(&[]), "");
	}
}

// See qos_test/tests/async_reaper for more tests
