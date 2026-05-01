//! qos-bridge host server

use std::{
	net::{Ipv4Addr, SocketAddr},
	time::Duration,
};

use qos_core::{
	io::{HostBridge, SocketAddress, StreamPool},
	protocol::services::boot::BridgeConfig,
};
use qos_host::{EnclaveInfo, ENCLAVE_INFO};

/// Host server implementation using `HostBridge::tcp_to_vsock`
pub struct BridgeServer {
	socket_placeholder: SocketAddress,
	info_url: String,
	host_port_override: Option<u16>,
}

impl BridgeServer {
	pub fn new(
		socket_placeholder: SocketAddress,
		control_url: String,
		host_port_override: Option<u16>,
	) -> Self {
		Self {
			socket_placeholder,
			info_url: control_url + ENCLAVE_INFO,
			host_port_override,
		}
	}

	/// Start the host side of the bridge, taking configuration from the enclave
	pub async fn serve(&self) {
		loop {
			match tokio::task::block_in_place(|| {
				ureq::get(&self.info_url).timeout(Duration::from_secs(1)).call()
			}) {
				Ok(info) => {
					if let Some(me) = info
						.into_json::<EnclaveInfo>()
						.expect("unable to parse enclave info response")
						.manifest_envelope
					{
						break self
							.run_bridges(&me.manifest.pivot.bridge_config)
							.await;
					}
				}
				Err(err) => eprintln!("unable to query enclave: {err}"),
			}

			println!("retrying enclave info query in 5s");
			tokio::time::sleep(Duration::from_secs(5)).await;
		}
	}

	// overrides `port` with `Self::host_port_override` if set
	fn host_port(&self, port: u16) -> u16 {
		self.host_port_override.unwrap_or(port)
	}

	async fn run_bridges(&self, configs: &Vec<BridgeConfig>) {
		for config in configs {
			let (host_port, host_ip_str) = match config {
				BridgeConfig::Client { port: _, host: _ } => {
					unimplemented!("client support pending")
				}
				BridgeConfig::Server { port, host } => {
					(self.host_port(*port), host)
				}
			};

			// derive the app socket, for vsock just use the app host port with same CID as the enclave socket,
			// with usock just add "<port>.appsock" suffix
			let app_socket = match self
				.socket_placeholder
				.with_port(config.port())
			{
				Ok(value) => value,
				Err(err) => {
					eprintln!("unable to derive app socket from enclave socket: {err:?}, tcp to vsock bridge will not start");
					return;
				}
			};

			let app_pool = match StreamPool::single(app_socket) {
				Ok(value) => value,
				Err(err) => {
					eprintln!("unable to create new app socket pool: {err:?}, tcp to vsock bridge will not start");
					return;
				}
			};

			let Ok(host_ip) = host_ip_str.parse::<Ipv4Addr>() else {
				eprintln!("unable to parse host ip for bridge configuration: {host_ip_str}");
				return;
			};
			let host_addr = SocketAddr::new(host_ip.into(), host_port);

			HostBridge::new(app_pool, host_addr).tcp_to_vsock().await;
		}
	}
}
