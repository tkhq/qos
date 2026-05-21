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
				ureq::get(&self.info_url)
					.timeout(Duration::from_secs(1))
					.call()
					.map_err(Box::new)
			}) {
				Ok(info) => {
					if let Some(me) = info
						.into_json::<EnclaveInfo>()
						.expect("unable to parse enclave info response")
						.manifest_envelope
					{
						let manifest = me.manifest();
						break self.run_bridges(manifest.bridge_config());
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

	fn run_bridges(&self, configs: &[BridgeConfig]) {
		let mut egress_enabled = false;

		for config in configs {
			match config {
				BridgeConfig::Client { port: _, host: _ } => {
					// NOTE: we ignore the host and port here as they are meant for firewall rules
					// TODO: figure out how to actually handle the firewall rules, see TVC-25

					// only run one instance as it covers ALL ports, the others are for firewalls
					if !egress_enabled {
						egress_enabled = true;
						self.run_egress_host_bridge();
					}
				}
				BridgeConfig::Server { port, host } => {
					self.run_ingress_bridge(
						config.port(),
						self.host_port(*port),
						host,
					);
				}
			}
		}
	}

	// dummy placeholder
	#[cfg(not(feature = "vm"))]
	#[allow(clippy::unused_self)]
	fn run_egress_host_bridge(&self) {
		panic!("unable to run egress without vm feature and vsock support");
	}

	// run the transparent host egress
	#[cfg(feature = "vm")]
	fn run_egress_host_bridge(&self) {
		const EGRESS_PORT: u32 = 1000; // reserved range so user ports don't interfere
		let vsock = self.socket_placeholder.vsock();
		let cid = vsock.cid();
		let flags = qos_core::io::vsock_svm_flags(vsock); // ensure we copy the flags as set

		tokio::task::spawn_blocking(move || {
			println!("qos_bridge: starting transparent egress host side");
			qos_core::egress::host_egress(cid, EGRESS_PORT, flags);
		});
	}

	fn run_ingress_bridge(
		&self,
		core_port: u16,
		host_port: u16,
		host_ip_str: &str,
	) {
		// derive the app socket, for vsock just use the app host port with same CID as the enclave socket,
		// with usock just add "<port>.appsock" suffix
		let app_socket = match self.socket_placeholder.with_port(core_port) {
			Ok(value) => value,
			Err(err) => {
				eprintln!(
					"unable to derive app socket from enclave socket: {err:?}, tcp to vsock bridge will not start"
				);
				return;
			}
		};

		let app_pool = match StreamPool::single(app_socket) {
			Ok(value) => value,
			Err(err) => {
				eprintln!(
					"unable to create new app socket pool: {err:?}, tcp to vsock bridge will not start"
				);
				return;
			}
		};

		let Ok(host_ip) = host_ip_str.parse::<Ipv4Addr>() else {
			eprintln!(
				"unable to parse host ip for bridge configuration: {host_ip_str}"
			);
			return;
		};
		let host_addr = SocketAddr::new(host_ip.into(), host_port);

		HostBridge::new(app_pool, host_addr).tcp_to_vsock();
	}
}
