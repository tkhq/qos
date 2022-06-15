//! Streaming socket based client to connect with [`server::Server`].
use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
	io::{self, SocketAddress, Stream},
	protocol::{ProtocolError, ProtocolMsg},
};

#[derive(Debug)]
pub enum ClientError {
	IOError(io::IOError),
	ProtocolError(ProtocolError),
	BorshError(borsh::maybestd::io::Error),
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

impl From<borsh::maybestd::io::Error> for ClientError {
	fn from(err: borsh::maybestd::io::Error) -> Self {
		Self::BorshError(err)
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

	/// Send a [`ProtocolMsg`] and wait for the response.
	pub fn send(
		&self,
		request: ProtocolMsg,
	) -> Result<ProtocolMsg, ClientError> {
		let stream = Stream::connect(&self.addr)?;

		stream.send(
			&request.try_to_vec().expect("ProtocolMsg can be serialized. qed."),
		)?;
		let response = stream.recv()?;
		ProtocolMsg::try_from_slice(&response).map_err(Into::into)
	}
}
