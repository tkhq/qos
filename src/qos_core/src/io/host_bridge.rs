use std::net::SocketAddr;

use futures::future::join_all;
use tokio::{
	io::copy_bidirectional,
	net::{TcpListener, TcpStream},
	task::JoinHandle,
};

use super::{IOError, Listener, Stream, StreamPool};

pub struct HostBridge {
	stream_pool: StreamPool,
	host_addr: SocketAddr,
}

impl HostBridge {
	/// Create a new `HostBridge` with given `StreamPool` VSOCK connections and target `SocketAddr`.
	/// NOTE: bridge operation is decided by run calls e.g. `tcp_to_vsock`.
	pub fn new(stream_pool: StreamPool, host_addr: SocketAddr) -> Self {
		// ensure we have ports to spare
		assert!(
			stream_pool.len() + usize::from(host_addr.port()) < u16::MAX.into()
		);

		Self { stream_pool, host_addr }
	}

	/// Create a TCP to VSOCK bridge using the provided `StreamPool` and `SocketAddr` from constructor.
	/// This consumes the `HostBridge` instance and starts background tasks that only return on unrecoverable errors.
	/// NOTE: this spawns a standalone tasks and *DOES NOT WAIT* for completion.
	pub async fn tcp_to_vsock(self) {
		tokio::spawn(async move {
			let streams = self.stream_pool.to_streams();
			let mut tasks = Vec::new();
			let mut host_addr = self.host_addr;

			for stream in streams {
				eprintln!("tcp to vsock bridge listening on tcp:{host_addr}");
				tasks.push(tokio::spawn(tcp_to_vsock(stream, host_addr)));
				// bump port by 1 for next listener
				host_addr.set_port(host_addr.port() + 1);
			}

			await_all(tasks).await;
		});
	}

	/// Create a VSOCK to TCP bridge using the provided `StreamPool` and `SocketAddr` from constructor.
	/// This consumes the `HostBridge` instance and starts background tasks that only return on unrecoverable errors.
	/// NOTE: this spawns a standalone tasks and *DOES NOT WAIT* for completion.
	pub async fn vsock_to_tcp(self) {
		tokio::spawn(async move {
			let listeners = self
				.stream_pool
				.listen()
				.expect("unable to listen on vsock connections");

			let mut tasks = Vec::new();
			let mut host_addr = self.host_addr;

			for listener in listeners {
				eprintln!("vsock to tcp bridge listening on vsock:TODO");
				tasks.push(tokio::spawn(vsock_to_tcp(listener, host_addr)));
				// bump port by 1 for next listener
				host_addr.set_port(host_addr.port() + 1);
			}

			await_all(tasks).await;
		});
	}
}

async fn await_all(tasks: Vec<JoinHandle<Result<(), IOError>>>) {
	let results = join_all(tasks).await;

	for result in results {
		match result {
				Err(err) => eprintln!("error on task joining: {err:?}"),
				Ok(result) => match result {
					Ok(()) => eprintln!("tcp to vsock bridge host exit, no errors. This shouldn't happen"), // TODO: error? panic?
					Err(err) => eprintln!("error in task: {err:?}"),
				},
			}
	}
}

// bridge tcp to vsock in an endless loop with 1s retry on errors
async fn tcp_to_vsock(
	enclave_stream: Stream,
	host_addr: SocketAddr,
) -> Result<(), IOError> {
	loop {
		let listener = match TcpListener::bind(host_addr).await {
			Ok(value) => value,
			Err(err) => {
				eprintln!(
					"error binding tcp addr {host_addr}: {err:?}, retrying"
				);
				continue;
			}
		};

		let mut tcp_stream = match listener.accept().await {
			Ok((value, _)) => value,
			Err(err) => {
				eprintln!(
					"error accepting connection on tcp addr {host_addr}: {err:?}, retrying"
				);
				continue;
			}
		};

		let mut stream = Stream::from(&enclave_stream);
		if let Err(err) = tokio::spawn(async move {
			if let Err(err) = stream.connect().await {
				eprintln!("error connecting to VSOCK {err:?}, retrying");
				return;
			}

			if let Err(err) =
				copy_bidirectional(&mut tcp_stream, &mut stream).await
			{
				eprintln!(
					"error on tcp to vsock stream bridge: {err:?}, retrying"
				);
			} else {
				eprintln!("tcp to vsock stream bridge shutdown, retrying");
			}
		})
		.await
		{
			eprintln!("error awaiting tcp_to_vsock bridge worker {err}");
		}
	}
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
				eprintln!(
					"error accepting connection on vsock: {err:?}, retrying"
				);
				continue;
			}
		};

		if let Err(err) = tokio::spawn(async move {
			let mut tcp_stream = match TcpStream::connect(host_addr).await {
				Ok(value) => value,
				Err(err) => {
					eprintln!(
						"error connecting to tcp addr {host_addr}: {err:?}, retrying"
					);
					return;
				}
			};

			if let Err(err) =
				copy_bidirectional(&mut enclave_stream, &mut tcp_stream).await
			{
				eprintln!(
					"error on vsock to tcp stream bridge: {err:?}, retrying"
				);
			} else {
				eprintln!("vsock to tcp stream bridge shutdown, retrying");
			}
		})
		.await
		{
			eprintln!("error awaiting vsock_to_tcp bridge worker {err}");
		}
	}
}
