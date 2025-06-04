//! Protocol proxy for our remote QOS net proxy
use std::{
	collections::HashMap,
	io::{Read, Write},
};

use borsh::BorshDeserialize;
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
	connections: HashMap<u32, ProxyConnection>,
	next_connection_id: u32,
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
			connections: HashMap::new(),
			max_connections: DEFAULT_MAX_CONNECTION_SIZE,
			next_connection_id: 0,
		}
	}

	#[must_use]
	pub fn new_with_max_connections(max_connections: usize) -> Self {
		Self {
			connections: HashMap::new(),
			max_connections,
			next_connection_id: 0,
		}
	}

	/// Save the connection in the proxy and assigns a connection ID
	fn save_connection(
		&mut self,
		connection: ProxyConnection,
	) -> Result<u32, QosNetError> {
		if self.connections.len() >= self.max_connections {
			return Err(QosNetError::TooManyConnections(self.max_connections));
		}
		let connection_id = self.next_id();
		if self.connections.contains_key(&connection_id) {
			// This should never happen because "next_id" auto-increments
			// Still, out of an abundance of caution, we error out here.
			return Err(QosNetError::DuplicateConnectionId(connection_id));
		}

		match self.connections.insert(connection_id, connection) {
			// Should never, ever happen because we checked above that the connection id was not present before proceeding.
			// We explicitly handle this case here out of paranoia. If this happens, it means saving this connection
			// overrode another. This is _very_ concerning.
			Some(_) => Err(QosNetError::ConnectionOverridden(connection_id)),
			// Normal case: no value was present before
			None => Ok(connection_id),
		}
	}

	// Simple convenience method to get the next connection ID
	// This function increments `next_connection_id` and wraps around once at u32::MAX
	fn next_id(&mut self) -> u32 {
		// Grab the next available ID
		let id = self.next_connection_id;

		// Increment the next_connection_id and wrap around if we're at u32::MAX
		self.next_connection_id = self.next_connection_id.wrapping_add(1);

		id
	}

	fn remove_connection(&mut self, id: u32) -> Result<(), QosNetError> {
		match self.get_connection(id) {
			Some(_) => {
				self.connections.remove(&id);
				Ok(())
			}
			None => Err(QosNetError::ConnectionIdNotFound(id)),
		}
	}

	fn get_connection(&mut self, id: u32) -> Option<&mut ProxyConnection> {
		self.connections.get_mut(&id)
	}

	/// Close a connection by its ID
	pub fn close(&mut self, connection_id: u32) -> ProxyMsg {
		match self.shutdown_and_remove_connection(connection_id) {
			Ok(_) => ProxyMsg::CloseResponse { connection_id },
			Err(e) => ProxyMsg::ProxyError(e),
		}
	}

	fn shutdown_and_remove_connection(
		&mut self,
		id: u32,
	) -> Result<(), QosNetError> {
		let conn = self
			.get_connection(id)
			.ok_or(QosNetError::ConnectionIdNotFound(id))?;
		conn.shutdown()?;
		self.remove_connection(id)
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
				let remote_ip = conn.ip.clone();
				match self.save_connection(conn) {
					Ok(connection_id) => {
						println!(
							"Connection to {hostname} established and saved as ID {connection_id}"
						);
						ProxyMsg::ConnectResponse { connection_id, remote_ip }
					}
					Err(e) => {
						println!("error saving connection: {e:?}");
						ProxyMsg::ProxyError(e)
					}
				}
			}
			Err(e) => {
				println!("error while establishing connection: {e:?}");
				ProxyMsg::ProxyError(e)
			}
		}
	}

	/// Create a new connection, targeting an IP address directly.
	/// address. The TCP connection is opened and saved in internal state.
	pub fn connect_by_ip(&mut self, ip: String, port: u16) -> ProxyMsg {
		match proxy_connection::ProxyConnection::new_from_ip(ip.clone(), port) {
			Ok(conn) => {
				let remote_ip = conn.ip.clone();
				match self.save_connection(conn) {
					Ok(connection_id) => {
						println!("Connection to {ip} established and saved as ID {connection_id}");
						ProxyMsg::ConnectResponse { connection_id, remote_ip }
					}
					Err(e) => {
						println!("error saving connection: {e:?}");
						ProxyMsg::ProxyError(e)
					}
				}
			}
			Err(e) => {
				println!("error while establishing connection: {e:?}");
				ProxyMsg::ProxyError(e)
			}
		}
	}

	/// Performs a Read on a connection
	pub fn read(&mut self, connection_id: u32, size: usize) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			let mut buf: Vec<u8> = vec![0; size];
			match conn.read(&mut buf) {
				Ok(0) => {
					// A zero-sized read indicates a successful/graceful
					// connection close. Close it on our side as well.
					match self.shutdown_and_remove_connection(connection_id) {
						Ok(_) => ProxyMsg::ReadResponse {
							connection_id,
							data: buf,
							size: 0,
						},
						Err(e) => ProxyMsg::ProxyError(e)
					}
				}
				Ok(size) => {
					ProxyMsg::ReadResponse { connection_id, data: buf, size }
				}
				Err(e) => match self.shutdown_and_remove_connection(connection_id) {
					Ok(_) => ProxyMsg::ProxyError(e.into()),
					// If we fail to shutdown / remove the connection we have 2 errors to communicate back up: the read error
					// and the close error. We combine them under a single `IOError`, in the message.
					Err(close_err) => ProxyMsg::ProxyError(
						QosNetError::IOError(
							format!(
								"unable to read from connection: {}. Warning: unable to cleanly close to underlying connection: {:?}",
								e,
								close_err,
							)
						)
					),
				}
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
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return borsh::to_vec(&ProxyMsg::ProxyError(
				QosNetError::OversizedPayload,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let resp = match ProxyMsg::try_from_slice(&req_bytes) {
			Ok(req) => match req {
				ProxyMsg::StatusRequest => {
					ProxyMsg::StatusResponse(self.connections.len())
				}
				ProxyMsg::ConnectByNameRequest {
					hostname,
					port,
					dns_resolvers,
					dns_port,
				} => self.connect_by_name(
					hostname.clone(),
					port,
					dns_resolvers,
					dns_port,
				),
				ProxyMsg::ConnectByIpRequest { ip, port } => {
					self.connect_by_ip(ip, port)
				}
				ProxyMsg::CloseRequest { connection_id } => {
					self.close(connection_id)
				}
				ProxyMsg::ReadRequest { connection_id, size } => {
					self.read(connection_id, size)
				}
				ProxyMsg::WriteRequest { connection_id, data } => {
					self.write(connection_id, data)
				}
				ProxyMsg::FlushRequest { connection_id } => {
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

		borsh::to_vec(&resp)
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
		let request = borsh::to_vec(&ProxyMsg::StatusRequest).unwrap();
		let response = proxy.process(request);
		let msg = ProxyMsg::try_from_slice(&response).unwrap();
		assert_eq!(msg, ProxyMsg::StatusResponse(0));
	}

	#[test]
	fn fetch_plaintext_http_from_api_turnkey_com() {
		let mut proxy = Proxy::new();
		assert_eq!(proxy.num_connections(), 0);

		let request = borsh::to_vec(&ProxyMsg::ConnectByNameRequest {
			hostname: "api.turnkey.com".to_string(),
			port: 443,
			dns_resolvers: vec!["8.8.8.8".to_string()],
			dns_port: 53,
		})
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
		let http_request =
			"GET / HTTP/1.1\r\nHost: api.turnkey.com\r\nConnection: close\r\n\r\n".to_string();

		let request = borsh::to_vec(&ProxyMsg::WriteRequest {
			connection_id,
			data: http_request.as_bytes().to_vec(),
		})
		.unwrap();
		let response = proxy.process(request);
		let msg: ProxyMsg = ProxyMsg::try_from_slice(&response).unwrap();
		assert!(matches!(
			msg,
			ProxyMsg::WriteResponse { connection_id: _, size: _ }
		));

		// Check that we now have an active connection
		assert_eq!(proxy.num_connections(), 1);

		let request =
			borsh::to_vec(&ProxyMsg::ReadRequest { connection_id, size: 512 })
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
	fn test_connection_id_wraps_around() {
		let mut proxy =
			Proxy::new_with_max_connections(DEFAULT_MAX_CONNECTION_SIZE);
		proxy.next_connection_id = u32::MAX;

		let connect_max = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect_max,
			ProxyMsg::ConnectResponse { connection_id: u32::MAX, remote_ip: _ }
		));

		//
		let connect_0 = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect_0,
			ProxyMsg::ConnectResponse { connection_id: 0, remote_ip: _ }
		));
	}

	#[test]
	fn test_connection_id_detects_duplicates() {
		let mut proxy =
			Proxy::new_with_max_connections(DEFAULT_MAX_CONNECTION_SIZE);

		let connect = proxy.connect_by_ip("8.8.8.8".to_string(), 53);
		assert!(matches!(
			connect,
			ProxyMsg::ConnectResponse { connection_id: 0, remote_ip: _ }
		));

		// The "next_connection_id" should move to 1 automatically for us
		assert_eq!(proxy.next_connection_id, 1);
		// Now we artificially "roll back" our "next_connection_id" to trigger a DuplicateConnectionId error
		proxy.next_connection_id = 0;

		assert_eq!(
			proxy.connect_by_ip("8.8.8.8".to_string(), 53),
			ProxyMsg::ProxyError(QosNetError::DuplicateConnectionId(0)),
		);
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
