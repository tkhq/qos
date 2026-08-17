//! Admission protocol for manifest-authorized ingress bridges.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tokio::task::{JoinHandle, JoinSet};

use crate::{
	io::{IOError, Listener, SocketAddress, Stream},
	protocol::services::boot::BridgeConfig,
};

/// VSOCK port reserved for the bridge lifecycle control connection.
///
/// Application bridge ports are `u16`, so `65_536` is the first VSOCK port that
/// cannot collide with a configured application bridge. The egress bridge uses
/// a separate reserved port (`EGRESS_VSOCK_PORT`) for transparent networking;
/// these are different protocols and must not share a port.
pub const BRIDGE_CONTROL_VSOCK_PORT: u32 = 65_536;

/// Maximum time allowed for a bridge admission exchange.
pub const BRIDGE_ADMISSION_TIMEOUT: std::time::Duration =
	std::time::Duration::from_secs(3);

/// A typed hash of the effective host-ingress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyHash(#[serde(with = "qos_hex::serde")] [u8; 32]);

impl PolicyHash {
	/// Wrap a SHA-256 digest as an ingress policy hash.
	#[must_use]
	pub const fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

fn canonicalize_bridge_config(
	bridge_config: &[BridgeConfig],
) -> Vec<BridgeConfig> {
	bridge_config.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect()
}

/// Hash the effective host-ingress policy.
///
/// The input must contain only the `BridgeConfig::Server` entries announced on
/// the control connection. Entries are canonically ordered by port and host, so
/// equivalent policies hash identically even if their manifest order differs.
///
/// # Errors
///
/// Returns an error if QOS canonical JSON serialization fails.
pub fn ingress_policy_hash(
	server_bridges: &[BridgeConfig],
) -> Result<PolicyHash, serde_json::Error> {
	let canonical = canonicalize_bridge_config(server_bridges);
	qos_json::hash(&canonical).map(PolicyHash::new)
}

/// Messages exchanged on the persistent bridge-control connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum BridgeControlMessage {
	/// Announce the policy for this enclave lifecycle.
	Policy {
		/// Ordered server bridge entries. Client entries are not included.
		server_bridges: Vec<BridgeConfig>,
		/// Whether the manifest also enables transparent client egress.
		egress_enabled: bool,
	},
}

/// Messages exchanged before a data VSOCK becomes a raw application stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum BridgeDataMessage {
	/// Request admission under one ingress policy.
	Open {
		/// Hash of the effective server bridge policy.
		policy_hash: PolicyHash,
	},
	/// The enclave accepted the connection.
	Accepted {
		/// Echo of the policy hash that was accepted.
		policy_hash: PolicyHash,
	},
	/// The enclave rejected the connection.
	Rejected,
}

/// Bind the enclave-side bridge-control endpoint.
///
/// The returned task owns the listener and every accepted lifecycle lease.
///
/// # Errors
///
/// Returns an error if the control listener cannot be bound.
pub fn serve_bridge_control(
	address: &SocketAddress,
	server_bridges: &[BridgeConfig],
	egress_enabled: bool,
) -> Result<JoinHandle<Result<(), IOError>>, IOError> {
	let listener = Listener::listen(address)?;
	let server_bridges = canonicalize_bridge_config(server_bridges);
	println!("bridge control listening on {}", listener.addr());

	Ok(tokio::spawn(async move {
		let mut leases = JoinSet::new();
		loop {
			tokio::select! {
				biased;
				result = leases.join_next(), if !leases.is_empty() => {
					if let Some(Err(err)) = result {
						eprintln!("bridge control lease task failed: {err:?}");
					}
				}
				result = listener.accept() => {
					let stream = result?;
					leases.spawn(serve_bridge_control_lease(
						stream,
						server_bridges.clone(),
						egress_enabled,
					));
				}
			}
		}
	}))
}

async fn serve_bridge_control_lease(
	mut stream: Stream,
	server_bridges: Vec<BridgeConfig>,
	egress_enabled: bool,
) {
	let policy =
		BridgeControlMessage::Policy { server_bridges, egress_enabled };
	let Ok(policy) = qos_json::to_vec(&policy) else {
		return;
	};
	if let Err(err) = stream.send(&policy).await {
		eprintln!("bridge control policy announcement failed: {err:?}");
		return;
	}

	// No heartbeat is required. Reading here keeps the control lease alive and
	// treats EOF or any unexpected message as lease termination.
	let _ = stream.recv().await;
}

/// Open a host-side bridge-control lifecycle lease and receive its policy.
///
/// # Errors
///
/// Returns an error if connection setup, transport, or policy decoding fails.
pub async fn open_bridge_control(
	address: &SocketAddress,
) -> Result<(Stream, Vec<BridgeConfig>, bool), IOError> {
	let mut stream = Stream::new(address);
	let admission = async {
		stream.connect().await?;

		// See https://github.com/rust-vmm/vhost-device/issues/963.
		#[cfg(feature = "qemu")]
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;

		let policy = stream.recv().await?;
		let policy: BridgeControlMessage =
			qos_json::from_slice(&policy).map_err(|_| IOError::UnknownError)?;
		let BridgeControlMessage::Policy { server_bridges, egress_enabled } =
			policy;
		if server_bridges
			.iter()
			.any(|config| !matches!(config, BridgeConfig::Server { .. }))
		{
			return Err(IOError::UnexpectedProxyConnection);
		}
		Ok((server_bridges, egress_enabled))
	};

	let policy = tokio::time::timeout(BRIDGE_ADMISSION_TIMEOUT, admission)
		.await
		.map_err(|_| IOError::ConnectTimeout)??;
	Ok((stream, policy.0, policy.1))
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use super::*;

	static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

	fn control_address() -> SocketAddress {
		let id = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
		SocketAddress::new_unix(format!(
			"/tmp/qos_bridge_control_{}_{}.sock",
			std::process::id(),
			id
		))
	}

	fn server(port: u16, host: &str) -> BridgeConfig {
		BridgeConfig::Server { port, host: host.into() }
	}

	#[test]
	fn ingress_hash_is_order_independent_but_tracks_policy_changes() {
		let original = vec![server(3000, "0.0.0.0"), server(4000, "127.0.0.1")];
		let reordered =
			vec![server(4000, "127.0.0.1"), server(3000, "0.0.0.0")];

		assert_eq!(
			ingress_policy_hash(&original).unwrap(),
			ingress_policy_hash(&reordered).unwrap()
		);
		assert_ne!(
			ingress_policy_hash(&original).unwrap(),
			ingress_policy_hash(&[
				server(3000, "127.0.0.1"),
				server(4000, "127.0.0.1"),
			])
			.unwrap()
		);
		assert_ne!(
			ingress_policy_hash(&original).unwrap(),
			ingress_policy_hash(&[
				server(3001, "0.0.0.0"),
				server(4000, "127.0.0.1"),
			])
			.unwrap()
		);
		assert_ne!(
			ingress_policy_hash(&original).unwrap(),
			ingress_policy_hash(&[server(3000, "0.0.0.0")]).unwrap()
		);
	}

	#[test]
	fn bridge_messages_use_qos_json() {
		let control_message = BridgeControlMessage::Policy {
			server_bridges: vec![server(3000, "0.0.0.0")],
			egress_enabled: true,
		};
		let encoded = qos_json::to_vec(&control_message).unwrap();
		assert_eq!(
			qos_json::from_slice::<BridgeControlMessage>(&encoded).unwrap(),
			control_message
		);

		let data_message = BridgeDataMessage::Accepted {
			policy_hash: PolicyHash::new([0xab; 32]),
		};
		let encoded = qos_json::to_vec(&data_message).unwrap();
		assert_eq!(
			qos_json::from_slice::<BridgeDataMessage>(&encoded).unwrap(),
			data_message
		);
	}

	#[tokio::test]
	async fn control_announces_policy_and_closes_with_server() {
		let address = control_address();
		let server_bridges = vec![server(3000, "0.0.0.0")];
		let server =
			serve_bridge_control(&address, &server_bridges, true).unwrap();
		let (mut lease, received, egress_enabled) =
			open_bridge_control(&address).await.unwrap();
		assert_eq!(received, server_bridges);
		assert!(egress_enabled);

		server.abort();
		let _ = server.await;
		let closed = tokio::time::timeout(
			std::time::Duration::from_secs(1),
			lease.recv(),
		)
		.await;
		assert!(closed.is_ok(), "control lease did not close");
		assert!(closed.unwrap().is_err());
	}

	#[tokio::test]
	async fn control_rejects_client_entries_in_server_policy() {
		let address = control_address();
		let server = serve_bridge_control(
			&address,
			&[BridgeConfig::Client { port: 443, host: None }],
			false,
		)
		.unwrap();

		assert!(open_bridge_control(&address).await.is_err());
		server.abort();
		let _ = server.await;
	}
}
