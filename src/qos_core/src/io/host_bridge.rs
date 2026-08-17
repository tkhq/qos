use std::net::SocketAddr;

use futures::future::join_all;
use tokio::{
	io::copy_bidirectional,
	net::{TcpListener, TcpStream},
	sync::mpsc,
	task::JoinHandle,
	task::JoinSet,
};

#[cfg(test)]
use crate::io::SocketAddress;
use crate::io::{BRIDGE_ADMISSION_TIMEOUT, BridgeDataMessage, PolicyHash};

use super::{IOError, Listener, Stream, StreamPool};

/// A bridge implementing streaming connectivity TCP -> VSOCK -> TCP in either direction
pub struct HostBridge {
	stream_pool: StreamPool,
	host_addr: SocketAddr,
}

impl HostBridge {
	/// Create a new `HostBridge` with given `StreamPool` VSOCK connections and target `SocketAddr`.
	/// NOTE: bridge operation is decided by run calls e.g. `tcp_to_vsock`.
	///
	/// # Panics
	/// This panics in case the pool size + start port is bigger than `u16::MAX`
	#[must_use]
	pub fn new(stream_pool: StreamPool, host_addr: SocketAddr) -> Self {
		// ensure we have ports to spare
		assert!(
			stream_pool.len() + usize::from(host_addr.port()) < u16::MAX.into()
		);

		Self { stream_pool, host_addr }
	}

	/// Bind a policy-admitted TCP-to-VSOCK bridge.
	///
	/// Binding completes before this function returns. The returned task owns
	/// all listeners and accepted relays. Aborting it closes both. Admission
	/// failures notify `stale_tx` so the caller can revoke the active policy.
	///
	/// # Errors
	///
	/// Returns an error if any host TCP listener cannot be bound.
	pub async fn tcp_to_vsock(
		self,
		policy_hash: PolicyHash,
		stale_tx: mpsc::UnboundedSender<()>,
	) -> Result<JoinHandle<Result<(), IOError>>, IOError> {
		let streams = self.stream_pool.to_streams();
		let mut bound = Vec::with_capacity(streams.len());
		let mut host_addr = self.host_addr;

		for stream in streams {
			let listener = TcpListener::bind(host_addr).await?;
			bound.push((stream, listener, host_addr));
			host_addr.set_port(host_addr.port() + 1);
		}

		Ok(tokio::spawn(async move {
			let mut listeners = JoinSet::new();
			for (stream, listener, host_addr) in bound {
				println!("tcp to vsock bridge listening on {host_addr}");
				let stale_tx = stale_tx.clone();
				listeners.spawn(tcp_to_vsock_listener(
					stream,
					listener,
					host_addr,
					policy_hash,
					stale_tx,
				));
			}

			let result = match listeners.join_next().await {
				Some(Ok(result)) => result,
				Some(Err(err)) => {
					eprintln!("admitted listener task failed: {err:?}");
					Err(IOError::UnknownError)
				}
				None => Ok(()),
			};
			let _ = stale_tx.send(());
			result
		}))
	}

	/// Create a VSOCK to TCP bridge using the provided `StreamPool` and
	/// `SocketAddr` from constructor. This consumes the `HostBridge`
	/// instance and starts background tasks that only return on
	/// unrecoverable errors.
	/// NOTE: this spawns a standalone tasks and *DOES NOT WAIT* for
	/// completion.
	///
	/// # Panics
	///
	/// Panics if the stream pool fails to bind its listeners.
	pub fn vsock_to_tcp(self) {
		println!("starting vsock to tcp host bridge @ {}", self.host_addr);
		tokio::spawn(async move {
			let listeners = self
				.stream_pool
				.listen()
				.expect("unable to listen on vsock connections");

			let mut tasks = Vec::new();
			let mut host_addr = self.host_addr;

			for listener in listeners {
				println!(
					"vsock to tcp bridge listening on {}",
					listener.addr()
				);
				tasks.push(tokio::spawn(vsock_to_tcp(listener, host_addr)));
				// bump port by 1 for next listener
				host_addr.set_port(host_addr.port() + 1);
			}

			await_all(tasks).await;
		});
	}

	/// Bind a policy-admitted VSOCK-to-TCP bridge.
	///
	/// The returned task owns all VSOCK listeners and accepted relays. A
	/// connection reaches the pivot only after presenting `policy_hash`.
	///
	/// # Errors
	///
	/// Returns an error if any enclave-side listener cannot be bound.
	pub fn vsock_to_tcp_admitted(
		self,
		policy_hash: PolicyHash,
	) -> Result<JoinHandle<Result<(), IOError>>, IOError> {
		let listeners = self.stream_pool.listen()?;
		let mut host_addr = self.host_addr;
		let mut bound = Vec::with_capacity(listeners.len());

		for listener in listeners {
			println!(
				"admitted vsock to tcp bridge listening on {}",
				listener.addr()
			);
			bound.push((listener, host_addr));
			host_addr.set_port(host_addr.port() + 1);
		}

		Ok(tokio::spawn(async move {
			let mut listener_tasks = JoinSet::new();
			for (listener, host_addr) in bound {
				listener_tasks.spawn(vsock_to_tcp_admitted(
					listener,
					host_addr,
					policy_hash,
				));
			}

			match listener_tasks.join_next().await {
				Some(Ok(result)) => result,
				Some(Err(err)) => {
					eprintln!("admitted listener task failed: {err:?}");
					Err(IOError::UnknownError)
				}
				None => Ok(()),
			}
		}))
	}
}

async fn await_all(tasks: Vec<JoinHandle<Result<(), IOError>>>) {
	let results = join_all(tasks).await;

	for result in results {
		match result {
			Err(err) => eprintln!("error on task joining: {err:?}"),
			Ok(result) => match result {
				Ok(()) => println!(
					"tcp to vsock bridge host exit, no errors. This shouldn't happen"
				),
				Err(err) => eprintln!("error in task: {err:?}"),
			},
		}
	}
}

async fn tcp_to_vsock_listener(
	enclave_stream: Stream,
	listener: TcpListener,
	host_addr: SocketAddr,
	policy_hash: PolicyHash,
	stale_tx: mpsc::UnboundedSender<()>,
) -> Result<(), IOError> {
	let mut relays = JoinSet::new();

	loop {
		tokio::select! {
			biased;
			result = relays.join_next(), if !relays.is_empty() => {
				if let Some(Err(err)) = result {
					eprintln!("tcp to vsock relay task failed: {err:?}");
				}
			}
			result = listener.accept() => {
				let (tcp_stream, _) = match result {
					Ok(value) => value,
					Err(err) => {
						eprintln!("error accepting connection on tcp addr {host_addr}: {err:?}");
						return Err(err.into());
					}
				};

				let stream = Stream::from(&enclave_stream);
				let stale_tx = stale_tx.clone();
				relays.spawn(async move {
					if let Err(err) = admitted_tcp_relay(
						tcp_stream,
						stream,
						policy_hash,
					).await {
						eprintln!("bridge data admission failed: {err:?}");
						let _ = stale_tx.send(());
					}
				});
			}
		}
	}
}

async fn admitted_tcp_relay(
	mut tcp_stream: TcpStream,
	mut enclave_stream: Stream,
	policy_hash: PolicyHash,
) -> Result<(), IOError> {
	let admission = async {
		enclave_stream.connect().await?;

		// See https://github.com/rust-vmm/vhost-device/issues/963.
		#[cfg(feature = "qemu")]
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;

		let request =
			qos_json::to_vec(&BridgeDataMessage::Open { policy_hash })
				.map_err(|_| IOError::UnknownError)?;
		enclave_stream.send(&request).await?;
		let response = enclave_stream.recv().await?;
		let response: BridgeDataMessage = qos_json::from_slice(&response)
			.map_err(|_| IOError::UnknownError)?;
		if response != (BridgeDataMessage::Accepted { policy_hash }) {
			return Err(IOError::UnexpectedProxyConnection);
		}
		Ok(())
	};

	tokio::time::timeout(BRIDGE_ADMISSION_TIMEOUT, admission)
		.await
		.map_err(|_| IOError::ConnectTimeout)??;

	if let Err(err) =
		copy_bidirectional(&mut tcp_stream, &mut enclave_stream).await
	{
		eprintln!("error on admitted tcp to vsock stream bridge: {err:?}");
	}
	Ok(())
}

// bridge vsock to tcp in an endless loop with 1s retry on errors
async fn vsock_to_tcp(
	enclave_listener: Listener,
	host_addr: SocketAddr,
) -> Result<(), IOError> {
	loop {
		let mut enclave_stream = match enclave_listener.accept().await {
			Ok(value) => value,
			Err(err) => {
				eprintln!("error accepting connection on vsock: {err:?}");
				continue;
			}
		};

		tokio::spawn(async move {
			let mut tcp_stream = match TcpStream::connect(host_addr).await {
				Ok(value) => value,
				Err(err) => {
					eprintln!(
						"error connecting to tcp addr {host_addr}: {err:?}"
					);
					return;
				}
			};

			if let Err(err) =
				copy_bidirectional(&mut enclave_stream, &mut tcp_stream).await
			{
				eprintln!("error on vsock to tcp stream bridge: {err:?}");
			}
		});
	}
}

async fn vsock_to_tcp_admitted(
	enclave_listener: Listener,
	host_addr: SocketAddr,
	policy_hash: PolicyHash,
) -> Result<(), IOError> {
	let mut relays = JoinSet::new();

	loop {
		tokio::select! {
			biased;
			result = relays.join_next(), if !relays.is_empty() => {
				if let Some(Err(err)) = result {
					eprintln!("vsock to tcp relay task failed: {err:?}");
				}
			}
			result = enclave_listener.accept() => {
				let stream = match result {
					Ok(stream) => stream,
					Err(err) => {
						eprintln!("error accepting admitted vsock connection: {err:?}");
						return Err(err);
					}
				};
				relays.spawn(admitted_vsock_relay(stream, host_addr, policy_hash));
			}
		}
	}
}

async fn admitted_vsock_relay(
	mut enclave_stream: Stream,
	host_addr: SocketAddr,
	policy_hash: PolicyHash,
) {
	let admitted = tokio::time::timeout(BRIDGE_ADMISSION_TIMEOUT, async {
		let request = enclave_stream.recv().await?;
		let request = qos_json::from_slice::<BridgeDataMessage>(&request)
			.map_err(|_| IOError::UnknownError)?;
		let accepted = matches!(
			request,
			BridgeDataMessage::Open { policy_hash: supplied }
				if supplied == policy_hash
		);
		let response = if accepted {
			BridgeDataMessage::Accepted { policy_hash }
		} else {
			BridgeDataMessage::Rejected
		};
		let response =
			qos_json::to_vec(&response).map_err(|_| IOError::UnknownError)?;
		enclave_stream.send(&response).await?;
		if accepted { Ok(()) } else { Err(IOError::UnexpectedProxyConnection) }
	})
	.await;

	match admitted {
		Ok(Ok(())) => {}
		Ok(Err(err)) => {
			eprintln!("rejecting bridge data connection: {err:?}");
			return;
		}
		Err(_) => {
			eprintln!("timed out waiting for bridge data admission");
			return;
		}
	}

	let mut tcp_stream = match TcpStream::connect(host_addr).await {
		Ok(value) => value,
		Err(err) => {
			eprintln!("error connecting to tcp addr {host_addr}: {err:?}");
			return;
		}
	};

	if let Err(err) =
		copy_bidirectional(&mut enclave_stream, &mut tcp_stream).await
	{
		eprintln!("error on admitted vsock to tcp stream bridge: {err:?}");
	}
}

#[cfg(test)]
mod tests {
	use std::{
		net::Ipv4Addr,
		sync::atomic::{AtomicUsize, Ordering},
	};

	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

	fn app_address() -> SocketAddress {
		let id = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
		SocketAddress::new_unix(format!(
			"/tmp/qos_admitted_bridge_{}_{}.sock",
			std::process::id(),
			id
		))
	}

	async fn free_tcp_address() -> SocketAddr {
		let listener =
			TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		listener.local_addr().unwrap()
	}

	async fn echo_server() -> (TcpListener, SocketAddr) {
		let listener =
			TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let address = listener.local_addr().unwrap();
		(listener, address)
	}

	#[tokio::test]
	async fn admitted_bridge_preserves_application_bytes() {
		let hash = PolicyHash::new([7; 32]);
		let app_address = app_address();
		let (pivot, pivot_address) = echo_server().await;
		let pivot_task = tokio::spawn(async move {
			let (mut stream, _) = pivot.accept().await.unwrap();
			let mut bytes = [0; 9];
			stream.read_exact(&mut bytes).await.unwrap();
			stream.write_all(&bytes).await.unwrap();
		});
		let enclave_bridge = HostBridge::new(
			StreamPool::single(app_address.clone()).unwrap(),
			pivot_address,
		)
		.vsock_to_tcp_admitted(hash)
		.unwrap();
		let host_address = free_tcp_address().await;
		let (stale_tx, _stale_rx) = mpsc::unbounded_channel();
		let host_bridge = HostBridge::new(
			StreamPool::single(app_address).unwrap(),
			host_address,
		)
		.tcp_to_vsock(hash, stale_tx)
		.await
		.unwrap();

		let mut client = TcpStream::connect(host_address).await.unwrap();
		let tls_like = [0x16, 0x03, 0x03, 0, 4, 1, 2, 3, 4];
		client.write_all(&tls_like).await.unwrap();
		let mut reply = [0; 9];
		client.read_exact(&mut reply).await.unwrap();
		assert_eq!(reply, tls_like);

		host_bridge.abort();
		enclave_bridge.abort();
		let _ = host_bridge.await;
		let _ = enclave_bridge.await;
		pivot_task.await.unwrap();
	}

	#[tokio::test]
	async fn wrong_hash_never_connects_to_pivot() {
		let app_address = app_address();
		let (pivot, pivot_address) = echo_server().await;
		let enclave_bridge = HostBridge::new(
			StreamPool::single(app_address.clone()).unwrap(),
			pivot_address,
		)
		.vsock_to_tcp_admitted(PolicyHash::new([1; 32]))
		.unwrap();
		let host_address = free_tcp_address().await;
		let (stale_tx, mut stale_rx) = mpsc::unbounded_channel();
		let host_bridge = HostBridge::new(
			StreamPool::single(app_address).unwrap(),
			host_address,
		)
		.tcp_to_vsock(PolicyHash::new([2; 32]), stale_tx)
		.await
		.unwrap();

		let mut client = TcpStream::connect(host_address).await.unwrap();
		client.write_all(b"not authorized").await.unwrap();
		tokio::time::timeout(
			std::time::Duration::from_secs(1),
			stale_rx.recv(),
		)
		.await
		.expect("host did not report stale policy");
		assert!(
			tokio::time::timeout(
				std::time::Duration::from_millis(100),
				pivot.accept()
			)
			.await
			.is_err(),
			"rejected data connection reached the pivot"
		);

		host_bridge.abort();
		enclave_bridge.abort();
		let _ = host_bridge.await;
		let _ = enclave_bridge.await;
	}

	#[tokio::test]
	async fn direct_vsock_service_receives_no_client_bytes() {
		let app_address = app_address();
		let listener = Listener::listen(&app_address).unwrap();
		let direct_task = tokio::spawn(async move {
			let mut stream = listener.accept().await.unwrap();
			let admission = stream.recv().await.unwrap();
			assert!(matches!(
				qos_json::from_slice::<BridgeDataMessage>(&admission).unwrap(),
				BridgeDataMessage::Open { .. }
			));
			let mut byte = [0];
			assert!(
				tokio::time::timeout(
					std::time::Duration::from_millis(200),
					stream.read_exact(&mut byte)
				)
				.await
				.is_err(),
				"client bytes arrived before admission"
			);
		});
		let host_address = free_tcp_address().await;
		let (stale_tx, _stale_rx) = mpsc::unbounded_channel();
		let host_bridge = HostBridge::new(
			StreamPool::single(app_address).unwrap(),
			host_address,
		)
		.tcp_to_vsock(PolicyHash::new([3; 32]), stale_tx)
		.await
		.unwrap();

		let mut client = TcpStream::connect(host_address).await.unwrap();
		client.write_all(b"TLS ClientHello").await.unwrap();
		direct_task.await.unwrap();
		host_bridge.abort();
		let _ = host_bridge.await;
	}

	#[tokio::test]
	async fn aborting_listener_closes_active_relay() {
		let hash = PolicyHash::new([4; 32]);
		let app_address = app_address();
		let (pivot, pivot_address) = echo_server().await;
		let pivot_task = tokio::spawn(async move {
			let (mut stream, _) = pivot.accept().await.unwrap();
			let mut byte = [0];
			stream.read_exact(&mut byte).await.unwrap();
			stream.write_all(&byte).await.unwrap();
			let _ = stream.read(&mut byte).await;
		});
		let enclave_bridge = HostBridge::new(
			StreamPool::single(app_address.clone()).unwrap(),
			pivot_address,
		)
		.vsock_to_tcp_admitted(hash)
		.unwrap();
		let host_address = free_tcp_address().await;
		let (stale_tx, _stale_rx) = mpsc::unbounded_channel();
		let host_bridge = HostBridge::new(
			StreamPool::single(app_address).unwrap(),
			host_address,
		)
		.tcp_to_vsock(hash, stale_tx)
		.await
		.unwrap();
		let mut client = TcpStream::connect(host_address).await.unwrap();
		client.write_all(&[9]).await.unwrap();
		let mut reply = [0];
		client.read_exact(&mut reply).await.unwrap();

		host_bridge.abort();
		let _ = host_bridge.await;
		let closed = tokio::time::timeout(
			std::time::Duration::from_secs(1),
			client.read(&mut reply),
		)
		.await
		.expect("active external connection did not close")
		.unwrap();
		assert_eq!(closed, 0);
		enclave_bridge.abort();
		let _ = enclave_bridge.await;
		pivot_task.await.unwrap();
	}
}
