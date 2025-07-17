//! Contains an abstraction to implement the standard library's Read/Write
//! traits with `ProxyMsg`s.
use std::pin::Pin;

use borsh::BorshDeserialize;
use qos_core::io::Stream;
use tokio::{
	io::{AsyncRead, AsyncWrite},
	sync::MutexGuard,
};

use crate::{error::QosNetError, proxy_msg::ProxyMsg};

/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
/// and plugged into the tokio-rustls via the AsyncWrite and AsyncRead traits
pub struct ProxyStream<'pool> {
	/// Stream we hold for this connection
	stream: MutexGuard<'pool, Stream>,
	/// Once a connection is established (successful `ConnectByName` or
	/// ConnectByIp request), this connection ID is set the u32 in
	/// `ConnectResponse`.
	pub connection_id: u128,
	/// The remote host this connection points to
	pub remote_hostname: Option<String>,
	/// The remote IP this connection points to
	pub remote_ip: String,
}

impl<'pool> ProxyStream<'pool> {
	/// Create a new AsyncProxyStream by targeting a hostname
	///
	/// # Arguments
	///
	/// * `stream` - the `Stream` picked from a `StreamPool` behind a `MutexGuard` (e.g. from `pool.get().await`)
	/// * `hostname` - the hostname to connect to (the remote qos_net proxy will
	///   resolve DNS)
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	/// * `dns_resolvers` - array of resolvers to use to resolve `hostname`
	/// * `dns_port` - DNS port to use while resolving DNS (typically: 53 or
	///   853)
	pub async fn connect_by_name(
		mut stream: MutexGuard<'pool, Stream>,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByNameRequest {
			hostname: hostname.clone(),
			port,
			dns_resolvers,
			dns_port,
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { connection_id, remote_ip } => {
					Ok(Self {
						stream,
						connection_id,
						remote_ip,
						remote_hostname: Some(hostname),
					})
				}
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Create a new ProxyStream by targeting an IP address directly.
	///
	/// # Arguments
	/// * `stream` - the `Stream` picked from a `StreamPool` behind a `MutexGuard` (e.g. from `pool.get().await`)
	/// * `ip` - the IP the remote qos_net proxy should connect to
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	pub async fn connect_by_ip(
		mut stream: MutexGuard<'pool, Stream>,
		ip: String,
		port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByIpRequest { ip, port })
			.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { connection_id, remote_ip } => {
					Ok(Self {
						stream,
						connection_id,
						remote_ip,
						remote_hostname: None,
					})
				}
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Refresh this connection after a request has been completed. This MUST be called
	/// after each successful rustls session.
	pub async fn refresh(&mut self) -> Result<(), QosNetError> {
		self.stream.reconnect().await?;

		Ok(())
	}
}

impl AsyncRead for ProxyStream<'_> {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_read(cx, buf)
	}
}

impl AsyncWrite for ProxyStream<'_> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_write(cx, buf)
	}

	fn poll_flush(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_flush(cx)
	}

	fn poll_shutdown(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_shutdown(cx)
	}
}
