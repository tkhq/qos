//! Protocol proxy for our remote QOS net proxy
use borsh::BorshDeserialize;
use qos_core::async_server::AsyncRequestProcessor;

use crate::{
	async_proxy_connection::AsyncProxyConnection, error::QosNetError,
	proxy_msg::ProxyMsg,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

pub const DEFAULT_MAX_CONNECTION_SIZE: usize = 512;

/// Socket<>TCP proxy to enable remote connections
pub struct AsyncProxy {
	connections: Vec<AsyncProxyConnection>,
	max_connections: usize,
}

impl Default for AsyncProxy {
	fn default() -> Self {
		Self::new()
	}
}

impl AsyncProxy {
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
		connection: AsyncProxyConnection,
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

	fn get_connection(&mut self, id: u32) -> Option<&mut AsyncProxyConnection> {
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
	pub async fn connect_by_name(
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
				match self.save_connection(conn) {
					Ok(()) => {
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
	pub async fn connect_by_ip(&mut self, ip: String, port: u16) -> ProxyMsg {
		match AsyncProxyConnection::new_from_ip(ip.clone(), port).await {
			Ok(conn) => {
				let connection_id = conn.id;
				let remote_ip = conn.ip.clone();
				match self.save_connection(conn) {
					Ok(()) => {
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
	pub async fn read(&mut self, connection_id: u32, size: usize) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			let mut buf: Vec<u8> = vec![0; size];
			match conn.read(&mut buf).await {
				Ok(0) => {
					// A zero-sized read indicates a successful/graceful
					// connection close. So we can safely remove it.
					match self.remove_connection(connection_id) {
						Ok(_) => {
							// Connection was successfully removed / closed
							ProxyMsg::ReadResponse {
								connection_id,
								data: buf,
								size: 0,
							}
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
	pub async fn write(
		&mut self,
		connection_id: u32,
		data: Vec<u8>,
	) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			match conn.write(&data).await {
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
	pub async fn flush(&mut self, connection_id: u32) -> ProxyMsg {
		if let Some(conn) = self.get_connection(connection_id) {
			match conn.flush().await {
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

impl AsyncRequestProcessor for AsyncProxy {
	async fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
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
				} => {
					self.connect_by_name(
						hostname.clone(),
						port,
						dns_resolvers,
						dns_port,
					)
					.await
				}
				ProxyMsg::ConnectByIpRequest { ip, port } => {
					self.connect_by_ip(ip, port).await
				}
				ProxyMsg::CloseRequest { connection_id } => {
					self.close(connection_id)
				}
				ProxyMsg::ReadRequest { connection_id, size } => {
					self.read(connection_id, size).await
				}
				ProxyMsg::WriteRequest { connection_id, data } => {
					self.write(connection_id, data).await
				}
				ProxyMsg::FlushRequest { connection_id } => {
					self.flush(connection_id).await
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
