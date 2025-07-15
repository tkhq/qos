//! Protocol proxy for our remote QOS net proxy
use borsh::BorshDeserialize;
use futures::Future;
use qos_core::{
	async_server::{AsyncSocketServer, SocketServerError},
	io::{AsyncListener, AsyncStream, AsyncStreamPool, IOError},
};

use crate::{
	async_proxy_connection::AsyncProxyConnection, error::QosNetError,
	proxy_msg::ProxyMsg,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Socket<>TCP proxy to enable remote connections
pub struct AsyncProxy {
	tcp_connection: Option<AsyncProxyConnection>,
	sock_stream: AsyncStream,
}

impl AsyncProxy {
	/// Create a new AsyncProxy from the given AsyncStream, with empty tcp_connection
	pub fn new(sock_stream: AsyncStream) -> Self {
		Self { tcp_connection: None, sock_stream }
	}

	/// Create a new connection by resolving a name into an IP
	/// address. The TCP connection is opened and saved in internal state.
	async fn connect_by_name(
		&mut self,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> ProxyMsg {
		match AsyncProxyConnection::new_from_name(
			hostname.clone(),
			port,
			dns_resolvers.clone(),
			dns_port,
		)
		.await
		{
			Ok(conn) => {
				let connection_id = conn.id;
				let remote_ip = conn.ip.clone();
				self.tcp_connection = Some(conn);
				println!("Connection to {hostname} established");
				ProxyMsg::ConnectResponse { connection_id, remote_ip }
			}
			Err(e) => {
				println!("error while establishing connection: {e:?}");
				ProxyMsg::ProxyError(e)
			}
		}
	}

	/// Create a new connection, targeting an IP address directly.
	/// address. The TCP connection is opened and saved in internal state.
	async fn connect_by_ip(&mut self, ip: String, port: u16) -> ProxyMsg {
		match AsyncProxyConnection::new_from_ip(ip.clone(), port).await {
			Ok(conn) => {
				let connection_id = conn.id;
				let remote_ip = conn.ip.clone();
				self.tcp_connection = Some(conn);
				println!("Connection to {ip} established and saved as ID {connection_id}");
				ProxyMsg::ConnectResponse { connection_id, remote_ip }
			}
			Err(e) => {
				println!("error while establishing connection: {e:?}");
				ProxyMsg::ProxyError(e)
			}
		}
	}

	// processes given `ProxyMsg` if it's a connection request or returns a `ProxyError` otherwise.
	async fn process_req(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return borsh::to_vec(&ProxyMsg::ProxyError(
				QosNetError::OversizedPayload,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let resp = match ProxyMsg::try_from_slice(&req_bytes) {
			Ok(req) => match req {
				// TODO: do we need this??
				ProxyMsg::StatusRequest => ProxyMsg::StatusResponse(0),
				ProxyMsg::ConnectByNameRequest {
					hostname,
					port,
					dns_resolvers,
					dns_port,
				} => {
					self.connect_by_name(
						hostname,
						port,
						dns_resolvers,
						dns_port,
					)
					.await
				}
				ProxyMsg::ConnectByIpRequest { ip, port } => {
					self.connect_by_ip(ip, port).await
				}
				_ => ProxyMsg::ProxyError(QosNetError::InvalidMsg),
			},
			Err(_) => ProxyMsg::ProxyError(QosNetError::InvalidMsg),
		};

		borsh::to_vec(&resp)
			.expect("Protocol message can always be serialized. qed!")
	}
}

impl AsyncProxy {
	async fn run(&mut self) -> Result<(), IOError> {
		loop {
			// Only try to process ProxyMsg content on the USOCK/VSOCK if we're not connected to TCP yet.
			// If we're connected, we should be a "dumb pipe" using the `tokio::io::copy_bidirectional`
			// which is handled in the connect functions above
			if self.tcp_connection.is_none() {
				let req_bytes = self.sock_stream.recv().await?;
				let resp_bytes = self.process_req(req_bytes).await;
				self.sock_stream.send(&resp_bytes).await?;
				if let Some(tcp_connection) = &mut self.tcp_connection {
					let (_, _) = tokio::io::copy_bidirectional(
						&mut self.sock_stream,
						&mut tcp_connection.tcp_stream,
					)
					.await?;

					// Once the "dumb pipe" is closed we need to clear our tcp_connection and refresh
					// the proxy socket stream by using shutdown
					self.tcp_connection = None;

					break Ok(()); // return to the accept loop
				}
			}
		}
	}
}

pub trait AsyncProxyServer {
	fn listen_proxy(
		pool: AsyncStreamPool,
	) -> impl Future<Output = Result<Box<Self>, SocketServerError>> + Send;
}

impl AsyncProxyServer for AsyncSocketServer {
	/// Listen on a tcp proxy server in a way that allows the USOCK/VSOCK to be used as a
	/// dumb pipe after getting the `connect*` calls.
	async fn listen_proxy(
		pool: AsyncStreamPool,
	) -> Result<Box<Self>, SocketServerError> {
		println!(
			"`AsyncSocketServer` proxy listening on pool size {}",
			pool.len()
		);

		let listeners = pool.listen()?;

		let mut tasks = Vec::new();
		for listener in listeners {
			let task =
				tokio::spawn(async move { accept_loop_proxy(listener).await });

			tasks.push(task);
		}

		Ok(Box::new(Self { pool, tasks }))
	}
}

async fn accept_loop_proxy(
	listener: AsyncListener,
) -> Result<(), SocketServerError> {
	loop {
		let stream = listener.accept().await?;
		let mut proxy = AsyncProxy::new(stream);
		proxy.run().await?;
	}
}
