//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].
use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
	io::{self, SocketAddress, Stream},
	protocol::msg::ProtocolMsg,
};

/// Enclave client error.
#[derive(Debug)]
pub enum ClientError {
	/// [`io::IOError`] wrapper.
	IOError(io::IOError),
	/// `borsh::maybestd::io::Error` wrapper.
	BorshError(borsh::maybestd::io::Error),
}

impl From<io::IOError> for ClientError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<borsh::maybestd::io::Error> for ClientError {
	fn from(err: borsh::maybestd::io::Error) -> Self {
		Self::BorshError(err)
	}
}

/// Client for communicating with the enclave [`crate::server::SocketServer`].
#[derive(Debug)]
pub struct Client {
	addr: SocketAddress,
}

impl Client {
	/// Create a new client.
	#[must_use]
	pub fn new(addr: SocketAddress) -> Self {
		Self { addr }
	}

	/// Send a [`ProtocolMsg`] and wait for the response.
	pub fn send(
		&self,
		request: &ProtocolMsg,
	) -> Result<ProtocolMsg, ClientError> {
		let stream = Stream::connect(&self.addr)?;

		stream.send(
			&request.try_to_vec().expect("ProtocolMsg can be serialized. qed."),
		)?;
		let response = stream.recv()?;
		ProtocolMsg::try_from_slice(&response).map_err(Into::into)
	}

	/// Send raw bytes.
	pub fn send_raw(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let stream = Stream::connect(&self.addr)?;

		stream.send(request)?;
		stream.recv().map_err(Into::into)
	}
}
