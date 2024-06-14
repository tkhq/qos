//! Contains an abstraction to implement the standard library's Read/Write
//! traits with `ProxyMsg`s.
use std::io::{ErrorKind, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::io::{SocketAddress, Stream, TimeVal};

use crate::{error::QosNetError, proxy_msg::ProxyMsg};

/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
pub struct ProxyStream {
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

impl ProxyStream {
	/// Create a new ProxyStream by targeting a hostname
	///
	/// # Arguments
	///
	/// * `addr` - the USOCK or VSOCK to connect to (this socket should be bound
	/// to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `timeout` - the timeout to connect with
	/// * `hostname` - the hostname to connect to (the remote qos_net proxy will
	/// resolve DNS)
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	/// * `dns_resolvers` - array of resolvers to use to resolve `hostname`
	/// * `dns_port` - DNS port to use while resolving DNS (typically: 53 or
	///   853)
	pub fn connect_by_name(
		addr: &SocketAddress,
		timeout: TimeVal,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, QosNetError> {
		let stream = Stream::connect(addr, timeout)?;
		let req = ProxyMsg::ConnectByNameRequest {
			hostname: hostname.clone(),
			port,
			dns_resolvers,
			dns_port,
		}
		.try_to_vec()
		.expect("ProtocolMsg can always be serialized.");
		stream.send(&req)?;
		let resp_bytes = stream.recv()?;

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
	/// to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `timeout` - the timeout to connect with
	/// * `ip` - the IP the remote qos_net proxy should connect to
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	pub fn connect_by_ip(
		addr: &SocketAddress,
		timeout: TimeVal,
		ip: String,
		port: u16,
	) -> Result<Self, QosNetError> {
		let stream: Stream = Stream::connect(addr, timeout)?;
		let req = ProxyMsg::ConnectByIpRequest { ip, port }
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");
		stream.send(&req)?;
		let resp_bytes = stream.recv()?;

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
	pub fn close(&mut self) -> Result<(), QosNetError> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout)?;
		let req = ProxyMsg::CloseRequest { connection_id: self.connection_id }
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");
		stream.send(&req)?;
		let resp_bytes = stream.recv()?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::CloseResponse { connection_id: _ } => Ok(()),
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}
}

impl Read for ProxyStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout)
			.map_err(|e| {
				std::io::Error::new(
			ErrorKind::NotConnected,
			format!("Error while connecting to socket (sending read request): {:?}", e),
		)
			})?;

		let req = ProxyMsg::ReadRequest {
			connection_id: self.connection_id,
			size: buf.len(),
		}
		.try_to_vec()
		.expect("ProtocolMsg can always be serialized.");
		stream.send(&req).map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!("QOS IOError: {:?}", e),
			)
		})?;
		let resp_bytes = stream.recv().map_err(|e| {
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
						return Err(std::io::Error::new(ErrorKind::InvalidData, format!("overflow: cannot read {} bytes into a buffer of {} bytes", data.len(), buf.len())));
					}

					// Copy data into buffer
					for (i, b) in data.iter().enumerate() {
						buf[i] = *b
					}
					println!("READ {}: read {} bytes", buf.len(), size);
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
}

impl Write for ProxyStream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout)
			.map_err(|e| {
				std::io::Error::new(
			ErrorKind::NotConnected,
			format!("Error while connecting to socket (sending read request): {:?}", e),
		)
			})?;

		let req = ProxyMsg::WriteRequest {
			connection_id: self.connection_id,
			data: buf.to_vec(),
		}
		.try_to_vec()
		.expect("ProtocolMsg can always be serialized.");
		stream.send(&req).map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!("QOS IOError sending WriteRequest: {:?}", e),
			)
		})?;

		let resp_bytes = stream.recv().map_err(|e| {
			std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError receiving bytes from stream after WriteRequest: {:?}", e),
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
					println!("WRITE {}: sent buf of {} bytes", buf.len(), size);
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

	fn flush(&mut self) -> Result<(), std::io::Error> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout)
			.map_err(|e| {
				std::io::Error::new(
			ErrorKind::NotConnected,
			format!("Error while connecting to socket (sending read request): {:?}", e),
				)
			})?;

		let req = ProxyMsg::FlushRequest { connection_id: self.connection_id }
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");

		stream.send(&req).map_err(|e| {
			std::io::Error::new(
				ErrorKind::Other,
				format!("QOS IOError sending FlushRequest: {:?}", e),
			)
		})?;

		let resp_bytes = stream.recv().map_err(|e| {
			std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError receiving bytes from stream after FlushRequest: {:?}", e),
		)
		})?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::FlushResponse { connection_id: _ } => {
					println!("FLUSH OK");
					Ok(())
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
}

#[cfg(test)]
mod test {

	use std::{io::ErrorKind, sync::Arc};

	use qos_core::server::RequestProcessor;
	use rustls::{RootCertStore, SupportedCipherSuite};

	use super::*;
	use crate::proxy::Proxy;

	#[test]
	fn can_fetch_tls_content_with_local_stream() {
		let host = "api.turnkey.com";
		let path = "/health";

		let mut stream = LocalStream::new_by_name(
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
		)
		.unwrap();
		assert_eq!(stream.num_connections(), 1);

		assert_eq!(stream.remote_hostname, Some("api.turnkey.com".to_string()));

		let root_store =
			RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };

		let server_name: rustls::pki_types::ServerName<'_> =
			host.try_into().unwrap();
		let config: rustls::ClientConfig = rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth();
		let mut conn =
			rustls::ClientConnection::new(Arc::new(config), server_name)
				.unwrap();
		let mut tls = rustls::Stream::new(&mut conn, &mut stream);

		let http_request = format!(
			"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
		);

		tls.write_all(http_request.as_bytes()).unwrap();
		let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
		assert!(matches!(ciphersuite, SupportedCipherSuite::Tls13(_)));

		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes);

		// Ignore eof errors: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
		assert!(
			read_to_end_result.is_ok()
				|| (read_to_end_result
					.is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof))
		);
		let response_text = std::str::from_utf8(&response_bytes).unwrap();
		assert!(response_text.contains("HTTP/1.1 200 OK"));
		assert!(response_text.contains("currentTime"));

		let closed = stream.close();
		assert!(closed.is_ok());
		assert_eq!(stream.num_connections(), 0);
	}

	/// Struct representing a stream, with direct access to the proxy.
	/// Useful in tests! :)
	struct LocalStream {
		proxy: Box<Proxy>,
		pub connection_id: u32,
		pub remote_hostname: Option<String>,
	}

	impl LocalStream {
		pub fn new_by_name(
			hostname: String,
			port: u16,
			dns_resolvers: Vec<String>,
			dns_port: u16,
		) -> Result<Self, QosNetError> {
			let req = ProxyMsg::ConnectByNameRequest {
				hostname: hostname.clone(),
				port,
				dns_resolvers,
				dns_port,
			}
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");
			let mut proxy = Box::new(Proxy::new());
			let resp_bytes = proxy.process(req);

			match ProxyMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProxyMsg::ConnectResponse {
						connection_id,
						remote_ip: _,
					} => Ok(Self {
						proxy,
						connection_id,
						remote_hostname: Some(hostname),
					}),
					_ => Err(QosNetError::InvalidMsg),
				},
				Err(_) => Err(QosNetError::InvalidMsg),
			}
		}

		pub fn close(&mut self) -> Result<(), QosNetError> {
			match self.proxy.close(self.connection_id) {
				ProxyMsg::CloseResponse { connection_id: _ } => Ok(()),
				_ => Err(QosNetError::InvalidMsg),
			}
		}

		pub fn num_connections(&self) -> usize {
			self.proxy.num_connections()
		}
	}

	impl Read for LocalStream {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
			let req = ProxyMsg::ReadRequest {
				connection_id: self.connection_id,
				size: buf.len(),
			}
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.proxy.process(req);

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
							return Err(std::io::Error::new(ErrorKind::InvalidData, format!("overflow: cannot read {} bytes into a buffer of {} bytes", data.len(), buf.len())));
						}

						// Copy data into buffer
						for (i, b) in data.iter().enumerate() {
							buf[i] = *b
						}
						println!("READ {}: read {} bytes", buf.len(), size);
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
	}

	impl Write for LocalStream {
		fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
			let req = ProxyMsg::WriteRequest {
				connection_id: self.connection_id,
				data: buf.to_vec(),
			}
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.proxy.process(req);

			match ProxyMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProxyMsg::WriteResponse { connection_id: _, size } => {
						if size == 0 {
							return Err(std::io::Error::new(
								ErrorKind::Interrupted,
								"failed Write",
							));
						}
						println!("WRITE {}: sent {} bytes", buf.len(), size,);
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

		fn flush(&mut self) -> Result<(), std::io::Error> {
			let req =
				ProxyMsg::FlushRequest { connection_id: self.connection_id }
					.try_to_vec()
					.expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.proxy.process(req);

			match ProxyMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProxyMsg::FlushResponse { connection_id: _ } => {
						println!("FLUSH OK");
						Ok(())
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
	}
}
