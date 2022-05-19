//! Streaming socket based client to connect with [`server::Server`].
use crate::{
	io::{self, SocketAddress, Stream},
	protocol::{ProtocolError, ProtocolMsg},
};

#[derive(Debug)]
pub enum ClientError {
	IOError(io::IOError),
	ProtocolError(ProtocolError),
	SerdeCBOR(serde_cbor::Error),
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

impl From<serde_cbor::Error> for ClientError {
	fn from(err: serde_cbor::Error) -> Self {
		Self::SerdeCBOR(err)
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

	/// Send a [`ProtocolMsg`] and return the response.
	pub fn send(
		&self,
		request: ProtocolMsg,
	) -> Result<ProtocolMsg, ClientError> {
		let stream = Stream::connect(&self.addr)?;
		stream.send(
			&serde_cbor::to_vec(&request)
				.expect("ProtocolMsg can be serialized. qed."),
		)?;
		let mut response = stream.recv()?;
		serde_cbor::from_slice(&mut response).map_err(Into::into)
	}
}
