//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].
use crate::io::{self, SocketAddress, Stream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{hint};

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
	lock: AtomicBool
}

impl Client {
	/// Create a new client.
	#[must_use]
	pub fn new(addr: SocketAddress) -> Self {
		let lock = AtomicBool::new(false);
		Self { addr, lock }
	}

	/// Send raw bytes and wait for a response.
	pub fn send(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let stream = Stream::connect(&self.addr)?;

		// Wait for this invocation to get its shot at creating vsock
		while self.lock.load(Ordering::SeqCst) {
			hint::spin_loop();
		}

		// Take lock while sending
		self.lock.store(true, Ordering::SeqCst);

		match stream.send(request) {
			Ok(_) => {
				let res = stream.recv().map_err(Into::into);
				self.lock.store(false, Ordering::SeqCst);
				res
			},
			Err(err) => {
				self.lock.store(false, Ordering::SeqCst);
				Err(ClientError::IOError(err))
			}
		}
	}
}
