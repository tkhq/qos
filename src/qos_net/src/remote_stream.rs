//! Contains a RemoteStream abstraction to use qos_net's RemoteRead/RemoteWrite under standard Read/Write traits
use std::io::{ErrorKind, Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::io::{SocketAddress, Stream, TimeVal};

use crate::{error::ProtocolError, processor::ProtocolMsg};


/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
pub struct RemoteStream {
	/// socket address and timeout to create the underlying Stream.
	/// Because `Stream` implements `drop` it can't be persisted here unfortunately...
	/// TODO: figure out if this can work?
	/// stream: Box<Stream>,
	addr: SocketAddress,
	timeout: TimeVal,
	/// Tracks the state of the remote stream
	/// After initialization the connection is is `None`.
	/// Once a remote connection is established (successful RemoteOpenByName or RemoteOpenByIp request), this connection ID is set the u32 in RemoteOpenResponse.
	pub connection_id: u32,
	/// The remote host this connection points to
	pub remote_hostname: Option<String>,
	/// The remote IP this connection points to
	pub remote_ip: String,
}

impl RemoteStream {
	/// Create a new RemoteStream by name
	/// `addr` is the USOCK or VSOCK to connect to (this socket should be bound to a qos_net proxy)
	/// `timeout` is the timeout applied to the socket
	/// `hostname` is the hostname to connect to (the remote qos_net proxy will resolve DNS)
	/// `port` is the port the remote qos_net proxy should connect to
	/// `dns_resolvers` and `dns_port` are the resolvers to use.
	pub fn new_by_name(
		addr: &SocketAddress,
		timeout: TimeVal,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, ProtocolError> {
		println!("creating new RemoteStream by name");
		let stream = Stream::connect(addr, timeout)?;
		let req = ProtocolMsg::RemoteOpenByNameRequest{ hostname: hostname.clone(), port, dns_resolvers, dns_port }.try_to_vec().expect("ProtocolMsg can always be serialized.");
		stream.send(&req)?;
		let resp_bytes = stream.recv()?;

		match ProtocolMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProtocolMsg::RemoteOpenResponse { connection_id, remote_ip } => {
					Ok(Self {
						addr: addr.clone(),
						timeout,
						connection_id,
						remote_ip,
						remote_hostname: Some(hostname),
					})
				},
				_ => {
					Err(ProtocolError::InvalidMsg)
				}
			},
			Err(_) => {
				Err(ProtocolError::InvalidMsg)
			}
		}
	}

	/// Create a new RemoteStream by IP
	/// `addr` is the USOCK or VSOCK to connect to (this socket should be bound to a qos_net proxy)
	/// `timeout` is the timeout applied to the socket
	/// `ip` and `port` are the IP and port to connect to (on the outside of the enclave)
	pub fn new_by_ip(
		addr: &SocketAddress,
		timeout: TimeVal,
		ip: String,
		port: u16,
	) -> Result<Self, ProtocolError> {
		let stream: Stream = Stream::connect(addr, timeout)?;
		let req = ProtocolMsg::RemoteOpenByIpRequest { ip, port }.try_to_vec().expect("ProtocolMsg can always be serialized.");
		stream.send(&req)?;
		let resp_bytes = stream.recv()?;

		match ProtocolMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProtocolMsg::RemoteOpenResponse { connection_id, remote_ip } => {
					Ok(Self {
						addr: addr.clone(),
						timeout,
						connection_id,
						remote_ip,
						remote_hostname: None,
					})
				},
				_ => {
					Err(ProtocolError::InvalidMsg)
				}
			},
			Err(_) => {
				Err(ProtocolError::InvalidMsg)
			}
		}
	}
}

impl Read for RemoteStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout).map_err(|e| std::io::Error::new(
			ErrorKind::NotConnected,
			format!("Error while connecting to socket (sending read request): {:?}", e),
		))?;

		let req = ProtocolMsg::RemoteReadRequest { connection_id: self.connection_id, size: buf.len() }.try_to_vec().expect("ProtocolMsg can always be serialized.");
		stream.send(&req).map_err(|e| std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError: {:?}", e),
		))?;
		let resp_bytes = stream.recv().map_err(|e| std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError: {:?}", e),
		))?;


		match ProtocolMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProtocolMsg::RemoteReadResponse { connection_id: _, size, data } => {
					if data.len() == 0 {
						return Err(std::io::Error::new(ErrorKind::Interrupted, "empty RemoteRead"));
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
				},
				_ => {
					return Err(std::io::Error::new(ErrorKind::InvalidData, "unexpected response"));
				}
			},
			Err(_) => {
				return Err(std::io::Error::new(ErrorKind::InvalidData, "cannot deserialize message"));
			}
		}
	}
}

impl Write for RemoteStream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let stream: Stream = Stream::connect(&self.addr, self.timeout).map_err(|e| std::io::Error::new(
			ErrorKind::NotConnected,
			format!("Error while connecting to socket (sending read request): {:?}", e),
		))?;;
 
		let req = ProtocolMsg::RemoteWriteRequest { connection_id: self.connection_id, data: buf.to_vec() }.try_to_vec().expect("ProtocolMsg can always be serialized.");
		stream.send(&req).map_err(|e| std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError sending RemoteWriteRequest: {:?}", e),
		))?;

		let resp_bytes = stream.recv().map_err(|e| std::io::Error::new(
			ErrorKind::Other,
			format!("QOS IOError receiving bytes from stream after RemoteWriteRequest: {:?}", e),
		))?;


		match ProtocolMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProtocolMsg::RemoteWriteResponse { connection_id: _, size } => {
					if size == 0 {
						return Err(std::io::Error::new(ErrorKind::Interrupted, "failed RemoteWrite"));
					}
					println!("WRITE {}: sent buf of {} bytes", buf.len(), size);
					Ok(size)
				},
				_ => {
					return Err(std::io::Error::new(ErrorKind::InvalidData, "unexpected response"));
				}
			},
			Err(_) => {
				return Err(std::io::Error::new(ErrorKind::InvalidData, "cannot deserialize message"));
			}
		}
	}

	// No-op because we can't flush a socket. We're not keeping any sort of client-side buffer here.
	fn flush(&mut self) -> Result<(), std::io::Error> {
		Ok(())
	}
}


#[cfg(test)]
mod test {

	use std::{io::ErrorKind, sync::Arc};

	use qos_core::server::RequestProcessor;
use rustls::RootCertStore;

	use crate::processor::Processor;

use super::*;

	#[test]
	fn can_fetch_tls_content_with_local_stream() {
		let host = "api.turnkey.com";
		let path = "/health";

		let mut stream = LocalStream::new_by_name(
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
		).unwrap();

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
		println!("=== making HTTP request: \n{http_request}");

		tls.write_all(http_request.as_bytes()).unwrap();
		let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

		println!("=== current ciphersuite: {:?}", ciphersuite.suite());
		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes);

		// Ignore eof errors: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
		assert!(
			read_to_end_result.is_ok()
				|| (read_to_end_result
					.is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof))
		);
		println!("{}", std::str::from_utf8(&response_bytes).unwrap());
	}

	#[test]
	fn can_fetch_tls_content_with_remote_stream() {
		let host = "api.turnkey.com";
		let path = "/health";

		let proxy_addr =
			nix::sys::socket::UnixAddr::new("/tmp/proxy.sock").unwrap();
		let addr: SocketAddress = SocketAddress::Unix(proxy_addr);
		let timeout = TimeVal::new(1, 0);
		
		let mut stream = RemoteStream::new_by_name(
			&addr,
			timeout,
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
		).unwrap();

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
		println!("=== making HTTP request: \n{http_request}");

		tls.write_all(http_request.as_bytes()).unwrap();
		let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

		println!("=== current ciphersuite: {:?}", ciphersuite.suite());
		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes);

		// Ignore eof errors: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
		assert!(
			read_to_end_result.is_ok()
				|| (read_to_end_result
					.is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof))
		);
		println!("{}", std::str::from_utf8(&response_bytes).unwrap());
	}


	/// Struct representing a connection, with direct access to the processor.
	/// Useful in tests.
	struct LocalStream {
		/// socket address and timeout to create the underlying Stream.
		/// Because `Stream` implements `drop` it can't be persisted here unfortunately...
		/// TODO: figure out if this can work?
		/// stream: Box<Stream>,
		processor: Box<Processor>,
		/// Tracks the state of the remote stream
		/// After initialization the connection is is `None`.
		/// Once a remote connection is established (successful RemoteOpenByName or RemoteOpenByIp request), this connection ID is set the u32 in RemoteOpenResponse.
		pub connection_id: u32,
		/// The remote host this connection points to
		pub remote_hostname: Option<String>,
		/// The remote IP this connection points to
		pub remote_ip: String,
	}

	impl LocalStream {
		pub fn new_by_name(
			hostname: String,
			port: u16,
			dns_resolvers: Vec<String>,
			dns_port: u16,
		) -> Result<Self, ProtocolError> {
			println!("creating new RemoteStream by name");
			let req = ProtocolMsg::RemoteOpenByNameRequest{ hostname: hostname.clone(), port, dns_resolvers, dns_port }.try_to_vec().expect("ProtocolMsg can always be serialized.");
			let mut processor = Box::new(Processor::new());
			let resp_bytes = processor.process(req);

			match ProtocolMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProtocolMsg::RemoteOpenResponse { connection_id, remote_ip } => {
						#[allow(unsafe_code)]
						unsafe {
							Ok(Self {
								processor,
								connection_id,
								remote_ip,
								remote_hostname: Some(hostname),
							})
						}
					},
					_ => {
						Err(ProtocolError::InvalidMsg)
					}
				},
				Err(_) => {
					Err(ProtocolError::InvalidMsg)
				}
			}
		}
	}

	impl Read for LocalStream {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
			let req = ProtocolMsg::RemoteReadRequest { connection_id: self.connection_id, size: buf.len() }.try_to_vec().expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.processor.process(req);

			match ProtocolMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProtocolMsg::RemoteReadResponse { connection_id: _, size, data } => {
						if data.len() == 0 {
							return Err(std::io::Error::new(ErrorKind::Interrupted, "empty RemoteRead"));
						}
						if data.len() > buf.len() {
							return Err(std::io::Error::new(ErrorKind::InvalidData, format!("overflow: cannot read {} bytes into a buffer of {} bytes", data.len(), buf.len())));
						}

						// Copy data into buffer
						for (i, b) in data.iter().enumerate() {
							buf[i] = *b
						}
						println!("READ {}: read {} bytes: |{}|", buf.len(), data.len(), qos_hex::encode(&data));
						Ok(size)
					},
					_ => {
						return Err(std::io::Error::new(ErrorKind::InvalidData, "unexpected response"));
					}
				},
				Err(_) => {
					return Err(std::io::Error::new(ErrorKind::InvalidData, "cannot deserialize message"));
				}
			}
		}
	}

	impl Write for LocalStream {
		fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
			let req = ProtocolMsg::RemoteWriteRequest { connection_id: self.connection_id, data: buf.to_vec() }.try_to_vec().expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.processor.process(req);


			match ProtocolMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProtocolMsg::RemoteWriteResponse { connection_id: _, size } => {
						if size == 0 {
							return Err(std::io::Error::new(ErrorKind::Interrupted, "failed RemoteWrite"));
						}
						println!("WRITE {}: sent buf of {} bytes: |{}|", buf.len(), size, qos_hex::encode(buf));
						Ok(size)
					},
					_ => {
						return Err(std::io::Error::new(ErrorKind::InvalidData, "unexpected response"));
					}
				},
				Err(_) => {
					return Err(std::io::Error::new(ErrorKind::InvalidData, "cannot deserialize message"));
				}
			}
		}

		// No-op because we can't flush a socket. We're not keeping any sort of client-side buffer here.
		fn flush(&mut self) -> Result<(), std::io::Error> {
			let req = ProtocolMsg::RemoteFlushRequest { connection_id: self.connection_id }.try_to_vec().expect("ProtocolMsg can always be serialized.");
			let resp_bytes = self.processor.process(req);


			match ProtocolMsg::try_from_slice(&resp_bytes) {
				Ok(resp) => match resp {
					ProtocolMsg::RemoteFlushResponse { connection_id: _ } => {
						println!("FLUSH OK");
						Ok(())
					},
					_ => {
						return Err(std::io::Error::new(ErrorKind::InvalidData, "unexpected response"));
					}
				},
				Err(_) => {
					return Err(std::io::Error::new(ErrorKind::InvalidData, "cannot deserialize message"));
				}
			}
		}
	}

}
