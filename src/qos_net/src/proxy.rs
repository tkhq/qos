//! Protocol proxy for our remote QOS net proxy
use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::server;

use crate::{
	error::QosNetError,
	proxy_connection::{self, ProxyConnection},
	proxy_msg::ProxyMsg,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

pub const DEFAULT_MAX_CONNECTION_SIZE: usize = 512;

/// Socket<>TCP proxy to enable remote connections
pub struct Proxy {
	connections: Vec<ProxyConnection>,
	max_connections: usize,
}

impl Default for Proxy {
	fn default() -> Self {
		Self::new()
	}
}

impl Proxy {
	/// Create a new `Self`.
	#[must_use]
	pub fn new() -> Self {
		Self {
			connections: vec![],
			max_connections: DEFAULT_MAX_CONNECTION_SIZE,
		}
	}

	#[must_use]
	pub fn new_with_max_connections(max_connections: usize) -> Self {
		Self { connections: vec![], max_connections }
	}

	fn save_connection(
		&mut self,
		connection: ProxyConnection,
	) -> Result<(), QosNetError> {
		if self.connections.iter().any(|c| c.id == connection.id) {
			Err(QosNetError::DuplicateConnectionId(connection.id))
		} else {
			if self.connections.len() >= self.max_connections {
				return Err(QosNetError::TooManyConnections(
					self.max_connections,
				));
			}
			self.connections.push(connection);
			Ok(())
		}
	}

	fn remove_connection(&mut self, id: u32) -> Result<(), QosNetError> {
		match self.connections.iter().position(|c| c.id == id) {
			Some(i) => {
				self.connections.remove(i);
				Ok(())
			}
			None => Err(QosNetError::ConnectionIdNotFound(id)),
		}
	}

	fn get_connection(&mut self, id: u32) -> Option<&mut ProxyConnection> {
		self.connections.iter_mut().find(|c| c.id == id)
	}

	/// Close a connection by its ID
	pub fn close(&mut self, connection_id: u32) -> ProxyMsg {
		match self.remove_connection(connection_id) {
			Ok(_) => ProxyMsg::CloseResponse { connection_id },
			Err(e) => ProxyMsg::ProxyError(e),
		}
	}

	/// Return the number of open remote connections
	pub fn num_connections(&self) -> usize {
		self.connections.len()
	}

	/// Create a new connection by resolving a name into an IP
	/// address. The TCP connection is opened and saved in internal state.
	pub fn connect_by_name(
		&mut self,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> ProxyMsg {
		match proxy_connection::ProxyConnection::new_from_name(
			hostname.clone(),
			port,
			dns_resolvers.clone(),
			dns_port,
		) {
			Ok(conn) => {
				let connection_id = conn.id;
				let remote_ip = conn.ip.clone();
				println!("called new_from_name successfully. Saving connection ID {connection_id}...");
				match self.save_connection(conn) {
					Ok(()) => {
						println!("Connection established and saved. Returning ConnectResponse to client");
						ProxyMsg::ConnectResponse { connection_id, remote_ip }
					}
					Err(e) => {
						println!("error saving connection.");
						ProxyMsg::ProxyError(e)
					}
				}
			}
			Err(e) => {
				println!("error calling new_from_name");
				ProxyMsg::ProxyError(e)
			}
		}
	}

	/// Create a new connection, targeting an IP address directly.
	/// address. The TCP connection is opened and saved in internal state.
	pub fn connect_by_ip(&mut self, ip: String, port: u16) -> ProxyMsg {
		match proxy_connection::ProxyConnection::new_from_ip(ip, port) {
			Ok(conn) => {
				let connection_id = conn.id;
				let remote_ip = conn.ip.clone();
				match self.save_connection(conn) {
					Ok(()) => {
						ProxyMsg::ConnectResponse { connection_id, remote_ip }
					}
					Err(e) => ProxyMsg::ProxyError(e),
				}
			}
			Err(e) => ProxyMsg::ProxyError(e),
		}
	}

	/// Performs a Read on a connection
	pub fn read(&mut self, connection_id: u32, size: usize) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			let mut buf: Vec<u8> = vec![0; size];
			match conn.read(&mut buf) {
				Ok(0) => {
					// A zero-sized read indicates a successful/graceful
					// connection close. So we can safely remove it.
					match self.remove_connection(connection_id) {
						Ok(_) => {
							ProxyMsg::ProxyError(QosNetError::ConnectionClosed)
						}
						Err(e) => ProxyMsg::ProxyError(e),
					}
				}
				Ok(size) => {
					ProxyMsg::ReadResponse { connection_id, data: buf, size }
				}
				Err(e) => match self.remove_connection(connection_id) {
					Ok(_) => ProxyMsg::ProxyError(e.into()),
					Err(e) => ProxyMsg::ProxyError(e),
				},
			}
		} else {
			ProxyMsg::ProxyError(QosNetError::ConnectionIdNotFound(
				connection_id,
			))
		}
	}

	/// Performs a Write on an existing connection
	pub fn write(&mut self, connection_id: u32, data: Vec<u8>) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			match conn.write(&data) {
				Ok(size) => ProxyMsg::WriteResponse { connection_id, size },
				Err(e) => ProxyMsg::ProxyError(e.into()),
			}
		} else {
			ProxyMsg::ProxyError(QosNetError::ConnectionIdNotFound(
				connection_id,
			))
		}
	}

	/// Performs a Flush on an existing TCP connection
	pub fn flush(&mut self, connection_id: u32) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			match conn.flush() {
				Ok(_) => ProxyMsg::FlushResponse { connection_id },
				Err(e) => ProxyMsg::ProxyError(e.into()),
			}
		} else {
			ProxyMsg::ProxyError(QosNetError::ConnectionIdNotFound(
				connection_id,
			))
		}
	}
}

impl server::RequestProcessor for Proxy {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		println!("Proxy processing request");
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return ProxyMsg::ProxyError(QosNetError::OversizedPayload)
				.try_to_vec()
				.expect("ProtocolMsg can always be serialized. qed.");
		}

		let resp = match ProxyMsg::try_from_slice(&req_bytes) {
			Ok(req) => match req {
				ProxyMsg::StatusRequest => {
					println!("Proxy processing StatusRequest");
					ProxyMsg::StatusResponse(self.connections.len())
				}
				ProxyMsg::ConnectByNameRequest {
					hostname,
					port,
					dns_resolvers,
					dns_port,
				} => {
					println!("Proxy connecting to {hostname}:{port}");
					let resp = self.connect_by_name(
						hostname.clone(),
						port,
						dns_resolvers,
						dns_port,
					);
					println!("Proxy connected to {hostname}:{port}");
					resp
				}
				ProxyMsg::ConnectByIpRequest { ip, port } => {
					println!("Proxy connecting to {ip}:{port}");
					self.connect_by_ip(ip, port)
				}
				ProxyMsg::CloseRequest { connection_id } => {
					println!("Proxy closing connection {connection_id}");
					self.close(connection_id)
				}
				ProxyMsg::ReadRequest { connection_id, size } => {
					println!("Proxy reading {size} bytes from connection {connection_id}");
					self.read(connection_id, size)
				}
				ProxyMsg::WriteRequest { connection_id, data } => {
					println!("Proxy writing to connection {connection_id}");
					self.write(connection_id, data)
				}
				ProxyMsg::FlushRequest { connection_id } => {
					println!("Proxy flushing connection {connection_id}");
					self.flush(connection_id)
				}
				ProxyMsg::ProxyError(_) => {
					ProxyMsg::ProxyError(QosNetError::InvalidMsg)
				}
				ProxyMsg::StatusResponse(_) => {
					ProxyMsg::ProxyError(QosNetError::InvalidMsg)
				}
				ProxyMsg::ConnectResponse {
					connection_id: _,
					remote_ip: _,
				} => ProxyMsg::ProxyError(QosNetError::InvalidMsg),
				ProxyMsg::CloseResponse { connection_id: _ } => {
					ProxyMsg::ProxyError(QosNetError::InvalidMsg)
				}
				ProxyMsg::WriteResponse { connection_id: _, size: _ } => {
					ProxyMsg::ProxyError(QosNetError::InvalidMsg)
				}
				ProxyMsg::FlushResponse { connection_id: _ } => {
					ProxyMsg::ProxyError(QosNetError::InvalidMsg)
				}
				ProxyMsg::ReadResponse {
					connection_id: _,
					size: _,
					data: _,
				} => ProxyMsg::ProxyError(QosNetError::InvalidMsg),
			},
			Err(_) => ProxyMsg::ProxyError(QosNetError::InvalidMsg),
		};

		resp.try_to_vec()
			.expect("Protocol message can always be serialized. qed!")
	}
}

#[cfg(test)]
mod test {
	use std::str::from_utf8;

	use server::RequestProcessor;

	use super::*;

	#[test]
	fn simple_status_request() {
		let mut proxy = Proxy::new();
		let request = ProxyMsg::StatusRequest.try_to_vec().unwrap();
		let response = proxy.process(request);
		let msg = ProxyMsg::try_from_slice(&response).unwrap();
		assert_eq!(msg, ProxyMsg::StatusResponse(0));
	}

	#[test]
	fn fetch_plaintext_http_from_api_turnkey_com() {
		let mut proxy = Proxy::new();
		assert_eq!(proxy.num_connections(), 0);

		let request = ProxyMsg::ConnectByNameRequest {
			hostname: "api.turnkey.com".to_string(),
			port: 443,
			dns_resolvers: vec!["8.8.8.8".to_string()],
			dns_port: 53,
		}
		.try_to_vec()
		.unwrap();
		let response = proxy.process(request);
		let msg = ProxyMsg::try_from_slice(&response).unwrap();
		let connection_id = match msg {
			ProxyMsg::ConnectResponse { connection_id, remote_ip: _ } => {
				connection_id
			}
			_ => {
				panic!("test failure: msg is not ConnectResponse")
			}
		};
		let http_request = "GET / HTTP/1.1\r\nHost: api.turnkey.com\r\nConnection: close\r\n\r\n".to_string();

		let request = ProxyMsg::WriteRequest {
			connection_id,
			data: http_request.as_bytes().to_vec(),
		}
		.try_to_vec()
		.unwrap();
		let response = proxy.process(request);
		let msg: ProxyMsg = ProxyMsg::try_from_slice(&response).unwrap();
		assert!(matches!(
			msg,
			ProxyMsg::WriteResponse { connection_id: _, size: _ }
		));

		// Check that we now have an active connection
		assert_eq!(proxy.num_connections(), 1);

		let request = ProxyMsg::ReadRequest { connection_id, size: 512 }
			.try_to_vec()
			.unwrap();
		let response = proxy.process(request);
		let msg: ProxyMsg = ProxyMsg::try_from_slice(&response).unwrap();
		let data = match msg {
			ProxyMsg::ReadResponse { connection_id: _, size: _, data } => data,
			_ => {
				panic!("test failure: msg is not ReadResponse")
			}
		};

		let response = from_utf8(&data).unwrap();
		assert!(response.contains("HTTP/1.1 400 Bad Request"));
		assert!(response.contains("plain HTTP request was sent to HTTPS port"));
	}

	#[test]
	fn error_when_connection_limit_is_reached() {
		let mut proxy = Proxy::new_with_max_connections(2);

		let connect1 = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect1,
			ProxyMsg::ConnectResponse { connection_id: _, remote_ip: _ }
		));
		assert_eq!(proxy.num_connections(), 1);

		let connect2 = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect2,
			ProxyMsg::ConnectResponse { connection_id: _, remote_ip: _ }
		));
		assert_eq!(proxy.num_connections(), 2);

		let connect3 = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect3,
			ProxyMsg::ProxyError(QosNetError::TooManyConnections(2))
		));
	}

	#[test]
	fn closes_connections() {
		let mut proxy = Proxy::new_with_max_connections(2);

		let connect = proxy.connect_by_ip("1.1.1.1".to_string(), 53);
		assert_eq!(proxy.num_connections(), 1);

		match connect {
			ProxyMsg::ConnectResponse { connection_id, remote_ip: _ } => {
				assert_eq!(
					proxy.close(connection_id),
					ProxyMsg::CloseResponse { connection_id }
				);
				assert_eq!(proxy.num_connections(), 0)
			}
			_ => panic!(
				"test failure: expected ConnectResponse and got: {connect:?}"
			),
		}
	}
}
