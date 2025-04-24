//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].

use crate::{client::ClientError, io::AsyncStreamPool};

/// Client for communicating with the enclave [`crate::server::SocketServer`].
pub struct AsyncClient {
	pool: AsyncStreamPool,
}

impl AsyncClient {
	/// Create a new client.
	#[must_use]
	pub fn new(pool: AsyncStreamPool) -> Self {
		Self { pool }
	}

	/// Send raw bytes and wait for a response until the clients configured
	/// timeout.
	pub async fn call(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		let mut stream = self.pool.get().await;
		let resp = stream.call(request).await?;

		Ok(resp)
	}
}
