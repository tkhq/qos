//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].

use std::time::Duration;

use crate::io::{IOError, SharedStreamPool, SocketAddress, StreamPool};

/// Enclave client error.
#[derive(Debug)]
pub enum ClientError {
	/// [`io::IOError`] wrapper.
	IOError(IOError),
	/// Deserialization error
	DeserializationError(String),
	/// Invalid enclave response to a request (e.g. mismatch)
	ResponseMismatch,
}

impl From<IOError> for ClientError {
	fn from(err: IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<serde_json::Error> for ClientError {
	fn from(err: serde_json::Error) -> Self {
		Self::DeserializationError(err.to_string())
	}
}
/// Client for communicating with the enclave `crate::server::SocketServer`.
#[derive(Clone, Debug)]
pub struct SocketClient {
	pool: SharedStreamPool,
	timeout: Duration,
}

impl SocketClient {
	/// Create a new client with given `StreamPool`.
	#[must_use]
	pub fn new(pool: SharedStreamPool, timeout: Duration) -> Self {
		Self { pool, timeout }
	}

	/// Create a new client from a single `SocketAddress`. This creates an implicit single socket `StreamPool`.
	pub fn single(
		addr: SocketAddress,
		timeout: Duration,
	) -> Result<Self, IOError> {
		let pool = StreamPool::new(addr, 1)?.shared();

		Ok(Self { pool, timeout })
	}

	/// Send raw bytes and wait for a response until the clients configured
	/// timeout.
	pub async fn call(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let pool = self.pool.read().await;

		// timeout should apply to the entire operation
		let timeout_result = tokio::time::timeout(self.timeout, async {
			let mut stream = pool.get().await;
			stream.call(request).await
		})
		.await;

		let resp = match timeout_result {
			Ok(result) => result?,
			Err(_err) => return Err(IOError::RecvTimeout.into()),
		};

		Ok(resp)
	}

	/// Sets the client's timeout value
	pub fn set_timeout(&mut self, timeout: Duration) {
		self.timeout = timeout;
	}

	/// Expands the underlying `AsyncPool` to given `pool_size`
	pub async fn expand_to(
		&mut self,
		pool_size: u8,
	) -> Result<(), ClientError> {
		self.pool.write().await.expand_to(pool_size)?;

		Ok(())
	}

	/// Attempt a one-off connection, used for tests
	pub async fn try_connect(&self) -> Result<(), IOError> {
		let pool = self.pool.read().await;
		let mut stream = pool.get().await;

		stream.connect().await
	}
}
