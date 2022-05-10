//! Streaming socket based client to connect with [`server::Server`].

use crate::{
	io::{self, SocketAddress, Stream},
	protocol::{ProtocolError, ProtocolMsg, Serialize},
};

#[derive(Debug)]
pub enum ClientError {
	IOError(io::IOError),
	ProtocolError(ProtocolError),
}

impl From<io::IOError> for ClientError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<ProtocolError> for ClientError {
	fn from(err: ProtocolError) -> Self {
		Self::ProtocolError(err)
	}
}

/// Client for communicating with the enclave [`server::Server`].
#[derive(Debug)]
pub struct Client {
	addr: SocketAddress,
}

impl Client {
	/// Create a new client.
	pub fn new(addr: SocketAddress) -> Self {
		Self { addr }
	}

	/// Send a [`ProtocolRequest`] and return the response.
	pub fn send(
		&self,
		request: ProtocolMsg,
	) -> Result<ProtocolMsg, ClientError> {
		let stream = Stream::connect(&self.addr)?;
		stream.send(&request.serialize())?;
		let mut response = stream.recv()?;
		ProtocolMsg::deserialize(&mut response).map_err(Into::into)
	}
}
