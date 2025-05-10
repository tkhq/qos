//! Contains an abstraction to implement the standard library's Read/Write
//! traits with `ProxyMsg`s.
use std::io::ErrorKind;

use borsh::BorshDeserialize;
use qos_core::io::{AsyncStream, SocketAddress, TimeVal};

use crate::{error::QosNetError, proxy_msg::ProxyMsg};

/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
pub struct AsyncProxyStream {
	/// socket address to create the underlying `Stream` over which we send
	/// `ProxyMsg`s
	addr: SocketAddress,
	/// timeout to create the underlying `Stream`
	timeout: TimeVal,
	/// Once a connection is established (successful `ConnectByName` or
	/// ConnectByIp request), this connection ID is set the u32 in
	/// `ConnectResponse`.
	pub connection_id: u32,
	/// The remote host this connection points to
	pub remote_hostname: Option<String>,
	/// The remote IP this connection points to
	pub remote_ip: String,
}

impl AsyncProxyStream {
	/// Create a new AsyncProxyStream by targeting a hostname
	///
	/// # Arguments
	///
	/// * `addr` - the USOCK or VSOCK to connect to (this socket should be bound
	///   to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `timeout` - the timeout to connect with
	/// * `hostname` - the hostname to connect to (the remote qos_net proxy will
	///   resolve DNS)
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	/// * `dns_resolvers` - array of resolvers to use to resolve `hostname`
	/// * `dns_port` - DNS port to use while resolving DNS (typically: 53 or
	///   853)
	pub async fn connect_by_name(
		addr: &SocketAddress,
		timeout: TimeVal,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, QosNetError> {
		let mut stream = AsyncStream::connect(addr, timeout).await?;
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
						addr: addr.clone(),
						timeout,
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
	/// * `addr` - the USOCK or VSOCK to connect to (this socket should be bound
	///   to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `timeout` - the timeout to connect with
	/// * `ip` - the IP the remote qos_net proxy should connect to
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	pub async fn connect_by_ip(
		addr: &SocketAddress,
		timeout: TimeVal,
		ip: String,
		port: u16,
	) -> Result<Self, QosNetError> {
		let mut stream = AsyncStream::connect(addr, timeout).await?;
		let req = borsh::to_vec(&ProxyMsg::ConnectByIpRequest { ip, port })
			.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { connection_id, remote_ip } => {
					Ok(Self {
						addr: addr.clone(),
						timeout,
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

	/// Close the remote connection
	pub async fn close(&mut self) -> Result<(), QosNetError> {
		let mut stream = AsyncStream::connect(&self.addr, self.timeout).await?;
		let req = borsh::to_vec(&ProxyMsg::CloseRequest {
			connection_id: self.connection_id,
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::CloseResponse { connection_id: _ } => Ok(()),
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}
}

impl AsyncProxyStream {
	pub async fn read(
		&mut self,
		buf: &mut [u8],
	) -> Result<usize, std::io::Error> {
		let mut stream = AsyncStream::connect(&self.addr, self.timeout)
			.await
			.map_err(|e| {
			std::io::Error::new(
				ErrorKind::NotConnected,
				format!("Error while connecting to socket (sending read request): {:?}", e),
			)
		})?;

		let req = borsh::to_vec(&ProxyMsg::ReadRequest {
			connection_id: self.connection_id,
			size: buf.len(),
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await.map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!("QOS IOError: {:?}", e),
			)
		})?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ReadResponse { connection_id: _, size, data } => {
					if data.is_empty() {
						return Err(std::io::Error::new(
							ErrorKind::Interrupted,
							"empty Read",
						));
					}
					if data.len() > buf.len() {
						return Err(std::io::Error::new(
							ErrorKind::InvalidData,
							format!(
								"overflow: cannot read {} bytes into a buffer of {} bytes",
								data.len(),
								buf.len()
							),
						));
					}

					// Copy data into buffer
					for (i, b) in data.iter().enumerate() {
						buf[i] = *b
					}
					Ok(size)
				}
				ProxyMsg::ProxyError(e) => Err(std::io::Error::new(
					ErrorKind::InvalidData,
					format!("Proxy error: {e:?}"),
				)),
				_ => Err(std::io::Error::new(
					ErrorKind::InvalidData,
					"unexpected response",
				)),
			},
			Err(_) => Err(std::io::Error::new(
				ErrorKind::InvalidData,
				"cannot deserialize message",
			)),
		}
	}

	pub async fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let mut stream = AsyncStream::connect(&self.addr, self.timeout)
			.await
			.map_err(|e| {
			std::io::Error::new(
				ErrorKind::NotConnected,
				format!("Error while connecting to socket (sending read request): {:?}", e),
			)
		})?;

		let req = borsh::to_vec(&ProxyMsg::WriteRequest {
			connection_id: self.connection_id,
			data: buf.to_vec(),
		})
		.expect("ProtocolMsg can always be serialized.");

		let resp_bytes = stream.call(&req).await.map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!("QOS IOError during write from stream call: {:?}", e),
			)
		})?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::WriteResponse { connection_id: _, size } => {
					if size == 0 {
						return Err(std::io::Error::new(
							ErrorKind::Interrupted,
							"Write failed: 0 bytes written",
						));
					}
					Ok(size)
				}
				_ => Err(std::io::Error::new(
					ErrorKind::InvalidData,
					"unexpected response",
				)),
			},
			Err(_) => Err(std::io::Error::new(
				ErrorKind::InvalidData,
				"cannot deserialize message",
			)),
		}
	}

	pub async fn flush(&mut self) -> Result<(), std::io::Error> {
		let mut stream: AsyncStream =
			AsyncStream::connect(&self.addr, self.timeout).await.map_err(
				|e| {
					std::io::Error::new(
				ErrorKind::NotConnected,
				format!("Error while connecting to socket (sending read request): {:?}", e),
			)
				},
			)?;

		let req = borsh::to_vec(&ProxyMsg::FlushRequest {
			connection_id: self.connection_id,
		})
		.expect("ProtocolMsg can always be serialized.");

		let resp_bytes = stream.call(&req).await.map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!(
					"QOS IOError during flush from stream after call: {:?}",
					e
				),
			)
		})?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::FlushResponse { connection_id: _ } => Ok(()),
				_ => Err(std::io::Error::new(
					ErrorKind::InvalidData,
					"unexpected response",
				)),
			},
			Err(_) => Err(std::io::Error::new(
				ErrorKind::InvalidData,
				"cannot deserialize message",
			)),
		}
	}
}
