//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].

use borsh::BorshDeserialize;

use crate::{io::{self, SocketAddress, Stream, TimeVal}, protocol::msg::ProtocolMsg};

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
		println!("[qos io: socket Client::send] start");
		if let Err(e) = ProtocolMsg::deserialize(&mut request) {
			println!("[qos io: socket Client::send] error deserilizing request {e}");
		}

		println!("[qos io: socket Client::send] about to connect");
		let stream = Stream::connect(&self.addr, self.timeout)?;
		println!("[qos io: socket Client::send] got stream={}", stream.fd);

		let send_res = stream.send(request);
		println!("[qos io: socket Client::send] send_res={:?}", send_res);
		send_res?;

		let recv_res = stream.recv().map_err(Into::into);
		println!("[qos io: socket Client::send] recv_res={:?}", recv_res);
		recv_res
	}
}
