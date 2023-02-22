//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].
use crate::io::{self, SocketAddress, Stream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{hint};

static GLOBAL_LOCK: AtomicBool = AtomicBool::new(false);

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

	/// Send raw bytes and wait for a response.
	pub fn send(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let stream = Stream::connect(&self.addr)?;

		// Wait for this invocation to get its shot at creating vsock
		while GLOBAL_LOCK.load(Ordering::SeqCst) {
			hint::spin_loop();
		}

		// Take lock while sending
		GLOBAL_LOCK.store(true, Ordering::SeqCst);

		let maybe_err = stream.send(request);

		// Return the slot after doing work
		GLOBAL_LOCK.store(false, Ordering::SeqCst);

		maybe_err?;

		stream.recv().map_err(Into::into)
	}
}
