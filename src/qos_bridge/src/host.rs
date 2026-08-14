//! qos-bridge host server

use std::{
	net::{Ipv4Addr, SocketAddr},
	time::Duration,
};

use qos_core::{
	io::{HostBridge, SocketAddress, StreamPool},
	protocol::services::boot::BridgeConfig,
};
use qos_host::{ENCLAVE_INFO, EnclaveInfo};
use tokio::task::JoinHandle;

/// Host server implementation using `HostBridge::tcp_to_vsock`
pub struct BridgeServer {
	socket_placeholder: SocketAddress,
	info_url: String,
	host_port_override: Option<u16>,
	#[allow(unused)]
	egress_bin_path: Option<String>,
}

impl BridgeServer {
	/// Create a new `BridgeServer` with  the given core socket placeholder, `control_url` and override port for local running
	#[must_use]
	pub fn new(
		socket_placeholder: SocketAddress,
		control_url: String,
		host_port_override: Option<u16>,
		egress_bin_path: Option<String>,
	) -> Self {
		Self {
			socket_placeholder,
			info_url: control_url + ENCLAVE_INFO,
			host_port_override,
			egress_bin_path,
		}
	}

	/// Start the host side of the bridge, taking configuration from the enclave.
	/// Keeps polling the enclave and reconciles ingress listeners whenever the
	/// approved manifest's bridge configuration changes.
	/// # Panics
	/// Panics if enclave info response fails to parse
	pub async fn serve(&self) {
		let mut egress_enabled = false;
		let mut active_servers = Vec::new();
		let mut server_handles = Vec::new();

		loop {
			match tokio::task::block_in_place(|| {
				ureq::get(&self.info_url)
					.timeout(Duration::from_secs(1))
					.call()
					.map_err(Box::new)
			}) {
				Ok(info) => {
					let configs = info
						.into_json::<EnclaveInfo>()
						.expect("unable to parse enclave info response")
						.manifest_envelope
						.map(|me| me.manifest().bridge_config().to_vec())
						.unwrap_or_default();

					if !egress_enabled
						&& configs.iter().any(|config| {
							matches!(config, BridgeConfig::Client { .. })
						}) {
						egress_enabled = true;
						self.run_egress_host_bridge();
					}

					self.reconcile_ingress(
						&configs,
						&mut active_servers,
						&mut server_handles,
					)
					.await;
				}
				Err(err) => eprintln!("unable to query enclave: {err}"),
			}

			tokio::time::sleep(Duration::from_secs(5)).await;
		}
	}

	// overrides `port` with `Self::host_port_override` if set
	fn host_port(&self, port: u16) -> u16 {
		self.host_port_override.unwrap_or(port)
	}

	async fn reconcile_ingress(
		&self,
		configs: &[BridgeConfig],
		active: &mut Vec<BridgeConfig>,
		handles: &mut Vec<JoinHandle<()>>,
	) {
		let servers: Vec<BridgeConfig> = configs
			.iter()
			.filter(|config| matches!(config, BridgeConfig::Server { .. }))
			.cloned()
			.collect();

		if servers == *active {
			return;
		}

		for handle in handles.drain(..) {
			handle.abort();
			let _ = handle.await;
		}

		for config in &servers {
			if let BridgeConfig::Server { port, host } = config
				&& let Some(handle) =
					self.run_ingress_bridge(*port, self.host_port(*port), host)
			{
				handles.push(handle);
			}
		}

		*active = servers;
	}

	// dummy placeholder
	#[cfg(not(feature = "egress"))]
	#[allow(clippy::unused_self)]
	fn run_egress_host_bridge(&self) {
		panic!("unable to run egress without vm feature and vsock support");
	}

	// run the transparent host egress as separate binary, non-blocking
	#[cfg(feature = "egress")]
	fn run_egress_host_bridge(&self) {
		let vsock = self.socket_placeholder.vsock();
		let cid = vsock.cid();
		let flags = qos_core::io::vsock_svm_flags(vsock); // ensure we copy the flags as set
		let vsock_to_host = flags == qos_core::io::VMADDR_FLAG_TO_HOST;
		let egress_bin_path: &str =
			self.egress_bin_path.as_deref().unwrap_or("/qos_egress");
		let args = &format!(
			"--egress-host --cid {cid} --vsock-to-host {vsock_to_host}",
		);

		println!("running egress bridge binary: {egress_bin_path} {args}");
		qos_core::egress::run_looping(egress_bin_path, &args);
	}

	fn run_ingress_bridge(
		&self,
		core_port: u16,
		host_port: u16,
		host_ip_str: &str,
	) -> Option<JoinHandle<()>> {
		// derive the app socket, for vsock just use the app host port with same CID as the enclave socket,
		// with usock just add "<port>.appsock" suffix
		let app_socket = match self.socket_placeholder.with_port(core_port) {
			Ok(value) => value,
			Err(err) => {
				eprintln!(
					"unable to derive app socket from enclave socket: {err:?}, tcp to vsock bridge will not start"
				);
				return None;
			}
		};

		let app_pool = match StreamPool::single(app_socket) {
			Ok(value) => value,
			Err(err) => {
				eprintln!(
					"unable to create new app socket pool: {err:?}, tcp to vsock bridge will not start"
				);
				return None;
			}
		};

		let Ok(host_ip) = host_ip_str.parse::<Ipv4Addr>() else {
			eprintln!(
				"unable to parse host ip for bridge configuration: {host_ip_str}"
			);
			return None;
		};
		let host_addr = SocketAddr::new(host_ip.into(), host_port);

		Some(HostBridge::new(app_pool, host_addr).tcp_to_vsock())
	}
}

#[cfg(test)]
mod tests {
	use tokio::net::TcpStream;

	use super::*;

	fn free_port() -> u16 {
		std::net::TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap()
			.port()
	}

	fn server_config(port: u16, host: &str) -> BridgeConfig {
		BridgeConfig::Server { port, host: host.to_string() }
	}

	async fn assert_connectable(port: u16) {
		for _ in 0..100 {
			if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
				return;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
		panic!("unable to connect to 127.0.0.1:{port}");
	}

	async fn assert_not_connectable(port: u16) {
		assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn reconcile_ingress_tracks_config_changes() {
		let bridge = BridgeServer::new(
			SocketAddress::new_unix(
				"/tmp/reconcile_ingress_tracks_config_changes.sock",
			),
			String::new(),
			None,
			None,
		);
		let mut active = Vec::new();
		let mut handles = Vec::new();

		let port_a = free_port();
		let port_b = free_port();

		bridge
			.reconcile_ingress(
				&[server_config(port_a, "0.0.0.0")],
				&mut active,
				&mut handles,
			)
			.await;
		assert_connectable(port_a).await;

		bridge
			.reconcile_ingress(
				&[server_config(port_a, "127.0.0.1")],
				&mut active,
				&mut handles,
			)
			.await;
		assert_connectable(port_a).await;

		bridge
			.reconcile_ingress(
				&[server_config(port_b, "127.0.0.1")],
				&mut active,
				&mut handles,
			)
			.await;
		assert_not_connectable(port_a).await;
		assert_connectable(port_b).await;

		bridge.reconcile_ingress(&[], &mut active, &mut handles).await;
		assert_not_connectable(port_b).await;
	}
}
