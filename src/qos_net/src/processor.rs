//! Protocol processor for our remote QOS net proxy
use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::server;

use crate::{
	error::ProtocolError,
	remote_connection::{self, RemoteConnection},
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct Processor {
	remote_connections: Vec<RemoteConnection>,
}

impl Default for Processor {
	fn default() -> Self {
		Self::new()
	}
}

impl Processor {
	/// Create a new `Self`.
	#[must_use]
	pub fn new() -> Self {
		Self { remote_connections: vec![] }
	}

	fn save_remote_connection(
		&mut self,
		connection: RemoteConnection,
	) -> Result<(), ProtocolError> {
		if self.remote_connections.iter().any(|c| c.id == connection.id) {
			Err(ProtocolError::DuplicateConnectionId(connection.id))
		} else {
			self.remote_connections.push(connection);
			Ok(())
		}
	}

	fn get_remote_connection(
		&mut self,
		id: u32,
	) -> Option<&mut RemoteConnection> {
		self.remote_connections.iter_mut().find(|c| c.id == id)
	}

	/// Open and save a new remote connection by resolving a name into an IP
	/// address, then opening a new TCP connection
	pub fn remote_open_by_name(
		&mut self,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> ProtocolMsg {
		println!("opening a new remote connection by hostname for {hostname}");

		match remote_connection::RemoteConnection::new_from_name(
			hostname.clone(),
			port,
			dns_resolvers.clone(),
			dns_port,
		) {
			Ok(remote_connection) => {
				let connection_id = remote_connection.id;
				let remote_ip = remote_connection.ip.clone();
				match self.save_remote_connection(remote_connection) {
					Ok(()) => ProtocolMsg::RemoteOpenResponse {
						connection_id,
						remote_ip,
					},
					Err(e) => ProtocolMsg::ProtocolErrorResponse(e),
				}
			}
			Err(e) => ProtocolMsg::ProtocolErrorResponse(e),
		}
	}

	/// Open a new remote connection by connecting to an IP address directly
	pub fn remote_open_by_ip(&mut self, ip: String, port: u16) -> ProtocolMsg {
		match remote_connection::RemoteConnection::new_from_ip(ip, port) {
			Ok(remote_connection) => {
				let connection_id = remote_connection.id;
				let remote_ip = remote_connection.ip.clone();
				match self.save_remote_connection(remote_connection) {
					Ok(()) => ProtocolMsg::RemoteOpenResponse {
						connection_id,
						remote_ip,
					},
					Err(e) => ProtocolMsg::ProtocolErrorResponse(e),
				}
			}
			Err(e) => ProtocolMsg::ProtocolErrorResponse(e),
		}
	}

	/// Performs a Read on a remote connection
	pub fn remote_read(
		&mut self,
		connection_id: u32,
		size: usize,
	) -> ProtocolMsg {
		if let Some(connection) = self.get_remote_connection(connection_id) {
			let mut buf: Vec<u8> = vec![0; size];
			match connection.read(&mut buf) {
				Ok(size) => {
					if size == 0 {
						ProtocolMsg::ProtocolErrorResponse(
							ProtocolError::RemoteConnectionClosed,
						)
					} else {
						ProtocolMsg::RemoteReadResponse {
							connection_id,
							data: buf,
							size,
						}
					}
				}
				Err(e) => ProtocolMsg::ProtocolErrorResponse(e.into()),
			}
		} else {
			ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::RemoteConnectionIdNotFound(connection_id),
			)
		}
	}

	/// Performs a Write on a remote connection
	pub fn remote_write(
		&mut self,
		connection_id: u32,
		data: Vec<u8>,
	) -> ProtocolMsg {
		if let Some(connection) = self.get_remote_connection(connection_id) {
			match connection.write(&data) {
				Ok(size) => {
					ProtocolMsg::RemoteWriteResponse { connection_id, size }
				}
				Err(e) => ProtocolMsg::ProtocolErrorResponse(e.into()),
			}
		} else {
			ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::RemoteConnectionIdNotFound(connection_id),
			)
		}
	}
	pub fn remote_flush(&mut self, connection_id: u32) -> ProtocolMsg {
		if let Some(connection) = self.get_remote_connection(connection_id) {
			match connection.flush() {
				Ok(_) => ProtocolMsg::RemoteFlushResponse { connection_id },
				Err(e) => ProtocolMsg::ProtocolErrorResponse(e.into()),
			}
		} else {
			ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::RemoteConnectionIdNotFound(connection_id),
			)
		}
	}
}

impl server::RequestProcessor for Processor {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			)
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let resp = match ProtocolMsg::try_from_slice(&req_bytes) {
			Ok(req) => match req {
				ProtocolMsg::StatusRequest => {
					ProtocolMsg::StatusResponse(self.remote_connections.len())
				}
				ProtocolMsg::RemoteOpenByNameRequest {
					hostname,
					port,
					dns_resolvers,
					dns_port,
				} => self.remote_open_by_name(
					hostname,
					port,
					dns_resolvers,
					dns_port,
				),
				ProtocolMsg::RemoteOpenByIpRequest { ip, port } => {
					self.remote_open_by_ip(ip, port)
				}
				ProtocolMsg::RemoteReadRequest { connection_id, size } => {
					println!("processing RemoteReadRequest");
					self.remote_read(connection_id, size)
				}
				ProtocolMsg::RemoteWriteRequest { connection_id, data } => {
					println!("processing RemoteWriteRequest");
					self.remote_write(connection_id, data)
				}
				ProtocolMsg::RemoteFlushRequest { connection_id } => {
					println!("processing RemoteWriteRequest");
					self.remote_flush(connection_id)
				}
				ProtocolMsg::ProtocolErrorResponse(_) => {
					ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::InvalidMsg,
					)
				}
				ProtocolMsg::StatusResponse(_) => {
					ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::InvalidMsg,
					)
				}
				ProtocolMsg::RemoteOpenResponse {
					connection_id: _,
					remote_ip: _,
				} => ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::InvalidMsg,
				),
				ProtocolMsg::RemoteWriteResponse {
					connection_id: _,
					size: _,
				} => ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::InvalidMsg,
				),
				ProtocolMsg::RemoteFlushResponse { connection_id: _ } => {
					ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::InvalidMsg,
					)
				}
				ProtocolMsg::RemoteReadResponse {
					connection_id: _,
					size: _,
					data: _,
				} => ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::InvalidMsg,
				),
			},
			Err(_) => {
				ProtocolMsg::ProtocolErrorResponse(ProtocolError::InvalidMsg)
			}
		};

		resp.try_to_vec()
			.expect("Protocol message can always be serialized. qed!")
	}
}

/// Message types to use with the remote proxy.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolMsg {
	/// A error from executing the protocol.
	ProtocolErrorResponse(ProtocolError),

	/// Request the status of the proxy server.
	StatusRequest,
	/// Response for [`Self::StatusRequest`], contains the number of opened
	/// connections
	StatusResponse(usize),

	/// Request from the enclave app to open a TCP connection to a remote host,
	/// by name This results in DNS resolution and new remote connection saved
	/// in protocol state
	RemoteOpenByNameRequest {
		/// The hostname to connect to, e.g. "www.googleapis.com"
		hostname: String,
		/// e.g. 443
		port: u16,
		/// An array of DNS resolvers e.g. ["8.8.8.8", "8.8.4.4"]
		dns_resolvers: Vec<String>,
		/// Port number to perform DNS resolution, e.g. 53
		dns_port: u16,
	},
	/// Request from the enclave app to open a TCP connection to a remote host,
	/// by IP This results in a new remote connection saved in protocol state
	RemoteOpenByIpRequest {
		/// The IP to connect to, e.g. "1.2.3.4"
		ip: String,
		/// e.g. 443
		port: u16,
	},
	/// Response for `RemoteOpenByNameRequest` and `RemoteOpenByIpRequest`
	RemoteOpenResponse {
		/// Connection ID to reference the opened connection when used with
		/// `RemoteRequest` and `RemoteResponse`. TODO: maybe we reply with a
		/// fd name directly? Not sure what this ID will map to.
		connection_id: u32,
		/// The remote host IP, e.g. "1.2.3.4"
		remote_ip: String,
	},
	/// Read from a remote connection
	RemoteReadRequest {
		/// A connection ID from `RemoteOpenResponse`
		connection_id: u32,
		/// number of bytes to read
		size: usize,
	},
	/// Response to `RemoteReadRequest` containing read data
	RemoteReadResponse {
		/// A connection ID from `RemoteOpenResponse`
		connection_id: u32,
		/// number of bytes read
		data: Vec<u8>,
		/// buffer after mutation from `read`. The first `size` bytes contain
		/// the result of the `read` call
		size: usize,
	},
	/// Write to a remote connection
	RemoteWriteRequest {
		/// A connection ID from `RemoteOpenResponse`
		connection_id: u32,
		/// Data to be sent
		data: Vec<u8>,
	},
	/// Response to `RemoteWriteRequest` containing the number of successfully
	/// written bytes.
	RemoteWriteResponse {
		/// Connection ID from `RemoteOpenResponse`
		connection_id: u32,
		/// Number of bytes written successfully
		size: usize,
	},
	/// Write to a remote connection
	RemoteFlushRequest {
		/// A connection ID from `RemoteOpenResponse`
		connection_id: u32,
	},
	/// Response to `RemoteFlushRequest`
	/// The response only contains the connection ID. Success is implicit: if
	/// the flush response fails, a ProtocolErrorResponse will be sent.
	RemoteFlushResponse {
		/// Connection ID from `RemoteOpenResponse`
		connection_id: u32,
	},
}

#[cfg(test)]
mod test {
	use std::str::from_utf8;

	use server::RequestProcessor;

	use super::*;

	#[test]
	fn simple_status_request() {
		let mut processor = Processor::new();
		let request = ProtocolMsg::StatusRequest.try_to_vec().unwrap();
		let response = processor.process(request.try_into().unwrap());
		let msg = ProtocolMsg::try_from_slice(&response).unwrap();
		assert_eq!(msg, ProtocolMsg::StatusResponse(0));
	}

	#[test]
	fn fetch_plaintext_http_from_api_turnkey_com() {
		let mut processor = Processor::new();
		let request = ProtocolMsg::RemoteOpenByNameRequest {
			hostname: "api.turnkey.com".to_string(),
			port: 443,
			dns_resolvers: vec!["8.8.8.8".to_string()],
			dns_port: 53,
		}
		.try_to_vec()
		.unwrap();
		let response = processor.process(request.try_into().unwrap());
		let msg = ProtocolMsg::try_from_slice(&response).unwrap();
		let connection_id = match msg {
			ProtocolMsg::RemoteOpenResponse { connection_id, remote_ip: _ } => {
				connection_id
			}
			_ => {
				panic!("test failure: ProtocolMsg is not RemoteOpenResponse")
			}
		};
		let http_request = "GET / HTTP/1.1\r\nHost: api.turnkey.com\r\nConnection: close\r\n\r\n".to_string();

		let request = ProtocolMsg::RemoteWriteRequest {
			connection_id,
			data: http_request.as_bytes().to_vec(),
		}
		.try_to_vec()
		.unwrap();
		let response = processor.process(request.try_into().unwrap());
		let msg: ProtocolMsg = ProtocolMsg::try_from_slice(&response).unwrap();
		assert!(matches!(
			msg,
			ProtocolMsg::RemoteWriteResponse { connection_id: _, size: _ }
		));

		let request =
			ProtocolMsg::RemoteReadRequest { connection_id, size: 512 }
				.try_to_vec()
				.unwrap();
		let response = processor.process(request.try_into().unwrap());
		let msg: ProtocolMsg = ProtocolMsg::try_from_slice(&response).unwrap();
		let data = match msg {
			ProtocolMsg::RemoteReadResponse {
				connection_id: _,
				size: _,
				data,
			} => data,
			_ => {
				panic!("test failure: ProtocolMsg is not RemoteReadResponse")
			}
		};

		let response = from_utf8(&data).unwrap();
		assert!(response.contains("HTTP/1.1 400 Bad Request"));
		assert!(response.contains("plain HTTP request was sent to HTTPS port"));
	}
}
