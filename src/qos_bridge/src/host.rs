//! `qos_bridge` host ingress supervisor.

use std::{
	net::{Ipv4Addr, SocketAddr},
	time::Duration,
};

use qos_core::{
	io::{
		BRIDGE_CONTROL_VSOCK_PORT, HostBridge, IOError, PolicyHash,
		SocketAddress, Stream, StreamPool, ingress_policy_hash,
		open_bridge_control,
	},
	protocol::services::boot::BridgeConfig,
};
use tokio::{sync::mpsc, task::JoinHandle};

const BRIDGE_CONTROL_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Host server which reconciles ingress against the current enclave lifecycle.
pub struct BridgeServer {
	socket_placeholder: SocketAddress,
	host_port_override: Option<u16>,
	#[allow(unused)]
	egress_bin_path: Option<String>,
}

struct ActiveIngress {
	control_stream: Stream,
	listener_handles: Vec<JoinHandle<Result<(), IOError>>>,
	_stale_tx: mpsc::UnboundedSender<()>,
	stale_rx: mpsc::UnboundedReceiver<()>,
}

impl ActiveIngress {
	async fn run_until_stale(mut self) {
		tokio::select! {
			biased;
			reason = self.stale_rx.recv() => {
				println!("revoking ingress after data admission failure: {reason:?}");
			}
			result = self.control_stream.recv() => {
				println!("revoking ingress after control lease ended: {result:?}");
			}
		}

		for handle in &self.listener_handles {
			handle.abort();
		}
		for handle in self.listener_handles {
			let _ = handle.await;
		}
	}
}

impl BridgeServer {
	/// Create a host ingress supervisor.
	#[must_use]
	pub fn new(
		socket_placeholder: SocketAddress,
		host_port_override: Option<u16>,
		egress_bin_path: Option<String>,
	) -> Self {
		Self { socket_placeholder, host_port_override, egress_bin_path }
	}

	/// Receive the current policy and supervise its ingress for the enclave
	/// lifecycle. No manifest endpoint is polled.
	///
	/// # Panics
	///
	pub async fn serve(&self) {
		let mut egress_started = false;
		let control_address = match self
			.socket_placeholder
			.with_system_port(BRIDGE_CONTROL_VSOCK_PORT)
		{
			Ok(address) => address,
			Err(err) => {
				eprintln!("unable to derive bridge control address: {err:?}");
				return;
			}
		};

		loop {
			let (control_stream, configs, egress_enabled) =
				match open_bridge_control(&control_address).await {
					Ok(policy) => policy,
					Err(err) => {
						eprintln!(
							"unable to open bridge control lease: {err:?}"
						);
						self.wait_to_retry().await;
						continue;
					}
				};

			let policy_hash = match ingress_policy_hash(&configs) {
				Ok(hash) => hash,
				Err(err) => {
					eprintln!("unable to hash ingress policy: {err}");
					self.wait_to_retry().await;
					continue;
				}
			};

			if egress_enabled && !egress_started {
				self.run_egress_host_bridge();
				egress_started = true;
			}

			match self
				.activate_ingress(control_stream, &configs, policy_hash)
				.await
			{
				Ok(active) => active.run_until_stale().await,
				Err(err) => {
					eprintln!("unable to activate ingress: {err:?}");
					self.wait_to_retry().await;
				}
			}
		}
	}

	async fn wait_to_retry(&self) {
		println!("retrying bridge control connection in 5s");
		tokio::time::sleep(BRIDGE_CONTROL_RETRY_DELAY).await;
	}

	async fn activate_ingress(
		&self,
		control_stream: Stream,
		configs: &[BridgeConfig],
		policy_hash: PolicyHash,
	) -> Result<ActiveIngress, IOError> {
		let (stale_tx, stale_rx) = mpsc::unbounded_channel();
		let mut listener_handles = Vec::new();

		for config in configs {
			let BridgeConfig::Server { port, host } = config else {
				continue;
			};
			match self
				.run_ingress_bridge(
					*port,
					self.host_port(*port),
					host,
					policy_hash,
					stale_tx.clone(),
				)
				.await
			{
				Ok(handle) => listener_handles.push(handle),
				Err(err) => {
					for handle in &listener_handles {
						handle.abort();
					}
					for handle in listener_handles {
						let _ = handle.await;
					}
					return Err(err);
				}
			}
		}

		println!(
			"activated ingress with {} listener(s)",
			listener_handles.len()
		);
		Ok(ActiveIngress {
			control_stream,
			listener_handles,
			_stale_tx: stale_tx,
			stale_rx,
		})
	}

	fn host_port(&self, port: u16) -> u16 {
		self.host_port_override.unwrap_or(port)
	}

	#[cfg(not(feature = "egress"))]
	#[allow(clippy::unused_self)]
	fn run_egress_host_bridge(&self) {
		panic!("unable to run egress without vm feature and vsock support");
	}

	#[cfg(feature = "egress")]
	fn run_egress_host_bridge(&self) {
		let vsock = self.socket_placeholder.vsock();
		let cid = vsock.cid();
		let flags = qos_core::io::vsock_svm_flags(vsock);
		let vsock_to_host = flags == qos_core::io::VMADDR_FLAG_TO_HOST;
		let egress_bin_path: &str =
			self.egress_bin_path.as_deref().unwrap_or("/qos_egress");
		let args = &format!(
			"--egress-host --cid {cid} --vsock-to-host {vsock_to_host}",
		);

		println!("running egress bridge binary: {egress_bin_path} {args}");
		qos_core::egress::run_looping(egress_bin_path, &args);
	}

	async fn run_ingress_bridge(
		&self,
		core_port: u16,
		host_port: u16,
		host_ip_str: &str,
		policy_hash: PolicyHash,
		stale_tx: mpsc::UnboundedSender<()>,
	) -> Result<JoinHandle<Result<(), IOError>>, IOError> {
		let app_socket = self.socket_placeholder.with_port(core_port)?;
		let app_pool = StreamPool::single(app_socket)?;
		let host_ip = host_ip_str
			.parse::<Ipv4Addr>()
			.map_err(|_| IOError::ConnectAddressInvalid)?;
		let host_addr = SocketAddr::new(host_ip.into(), host_port);

		HostBridge::new(app_pool, host_addr)
			.tcp_to_vsock(policy_hash, stale_tx)
			.await
	}
}

#[cfg(test)]
mod tests {
	use std::{
		net::UdpSocket,
		sync::atomic::{AtomicUsize, Ordering},
	};

	use qos_core::io::serve_bridge_control;
	use tokio::net::{TcpListener, TcpStream};

	use super::*;

	static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

	fn socket_placeholder() -> SocketAddress {
		let id = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
		SocketAddress::new_unix(format!(
			"/tmp/qos_bridge_lifecycle_{}_{}.sock",
			std::process::id(),
			id
		))
	}

	async fn free_port() -> u16 {
		TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
			.await
			.unwrap()
			.local_addr()
			.unwrap()
			.port()
	}

	fn non_loopback_ipv4() -> Option<Ipv4Addr> {
		let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
		socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
		match socket.local_addr().ok()?.ip() {
			std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
			_ => None,
		}
	}

	fn start_enclave_bridges(
		placeholder: &SocketAddress,
		configs: &[BridgeConfig],
	) -> Vec<JoinHandle<Result<(), IOError>>> {
		let server_bridges = configs.to_vec();
		let hash = ingress_policy_hash(&server_bridges).unwrap();
		let mut workers = Vec::new();
		for config in configs {
			let BridgeConfig::Server { port, .. } = config else {
				continue;
			};
			let app_address = placeholder.with_port(*port).unwrap();
			let app_pool = StreamPool::single(app_address).unwrap();
			let pivot_address =
				SocketAddr::new(Ipv4Addr::LOCALHOST.into(), *port);
			workers.push(
				HostBridge::new(app_pool, pivot_address)
					.vsock_to_tcp_admitted(hash)
					.unwrap(),
			);
		}
		let control_address =
			placeholder.with_system_port(BRIDGE_CONTROL_VSOCK_PORT).unwrap();
		workers.push(
			serve_bridge_control(&control_address, &server_bridges, false)
				.unwrap(),
		);
		workers
	}

	async fn activate_for(
		server: &BridgeServer,
		placeholder: &SocketAddress,
		configs: &[BridgeConfig],
	) -> ActiveIngress {
		let control_address =
			placeholder.with_system_port(BRIDGE_CONTROL_VSOCK_PORT).unwrap();
		let (control_stream, announced, egress_enabled) =
			open_bridge_control(&control_address).await.unwrap();
		assert_eq!(announced, configs);
		assert!(!egress_enabled);
		let hash = ingress_policy_hash(&announced).unwrap();
		server.activate_ingress(control_stream, &announced, hash).await.unwrap()
	}

	async fn stop_workers(workers: Vec<JoinHandle<Result<(), IOError>>>) {
		for worker in &workers {
			worker.abort();
		}
		for worker in workers {
			let _ = worker.await;
		}
	}

	async fn wait_for_revocation(active: ActiveIngress) {
		tokio::time::timeout(Duration::from_secs(1), active.run_until_stale())
			.await
			.expect("ingress did not revoke after enclave shutdown");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn same_socket_replacement_narrows_then_removes_listener() {
		let placeholder = socket_placeholder();
		let app_port = free_port().await;
		let host_port = free_port().await;
		let external_ip = non_loopback_ipv4();
		let server =
			BridgeServer::new(placeholder.clone(), Some(host_port), None);

		let public = vec![BridgeConfig::Server {
			port: app_port,
			host: "0.0.0.0".into(),
		}];
		let public_workers = start_enclave_bridges(&placeholder, &public);
		let public_active = activate_for(&server, &placeholder, &public).await;
		if let Some(external_ip) = external_ip {
			assert!(
				tokio::time::timeout(
					Duration::from_secs(1),
					TcpStream::connect((external_ip, host_port))
				)
				.await
				.expect("public listener connection timed out")
				.is_ok(),
				"public listener did not accept on the external address"
			);
		}

		stop_workers(public_workers).await;
		wait_for_revocation(public_active).await;

		let narrowed = vec![BridgeConfig::Server {
			port: app_port,
			host: "127.0.0.1".into(),
		}];
		let narrowed_workers = start_enclave_bridges(&placeholder, &narrowed);
		let narrowed_active =
			activate_for(&server, &placeholder, &narrowed).await;
		assert!(
			TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).await.is_ok()
		);
		if let Some(external_ip) = external_ip {
			assert!(
				tokio::time::timeout(
					Duration::from_millis(200),
					TcpStream::connect((external_ip, host_port))
				)
				.await
				.expect("narrowed listener connection timed out")
				.is_err(),
				"narrowed listener accepted on the external address"
			);
		}

		stop_workers(narrowed_workers).await;
		wait_for_revocation(narrowed_active).await;

		let removed = Vec::new();
		let removed_workers = start_enclave_bridges(&placeholder, &removed);
		let removed_active =
			activate_for(&server, &placeholder, &removed).await;
		assert!(
			TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).await.is_err()
		);

		stop_workers(removed_workers).await;
		wait_for_revocation(removed_active).await;
	}
}
