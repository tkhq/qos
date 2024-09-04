//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].

use crate::io::{self, SocketAddress, Stream, TimeVal};

/// Enclave client error.
#[derive(Debug)]
pub enum ClientError {
	/// [`io::IOError`] wrapper.
	IOError(io::IOError),
	/// `borsh::io::Error` wrapper.
	BorshError(borsh::io::Error),
}

impl From<io::IOError> for ClientError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<borsh::io::Error> for ClientError {
	fn from(err: borsh::io::Error) -> Self {
		Self::BorshError(err)
	}
}

/// Client for communicating with the enclave [`crate::server::SocketServer`].
#[derive(Debug, Clone)]
pub struct Client {
	addr: SocketAddress,
	timeout: TimeVal,
}

impl Client {
	/// Create a new client.
	#[must_use]
	pub fn new(addr: SocketAddress, timeout: TimeVal) -> Self {
		Self { addr, timeout }
	}

	/// Send raw bytes and wait for a response until the clients configured
	/// timeout.
	pub fn send(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let stream = Stream::connect(&self.addr, self.timeout)?;
		stream.send(request)?;
		stream.recv().map_err(Into::into)
	}
}
