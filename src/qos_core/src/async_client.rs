//! Streaming socket based client to connect with
//! [`crate::server::SocketServer`].

use crate::{client::ClientError, io::SharedAsyncStreamPool};

/// Client for communicating with the enclave `crate::server::SocketServer`.
#[derive(Clone, Debug)]
pub struct AsyncClient {
	pool: SharedAsyncStreamPool,
}

impl AsyncClient {
	/// Create a new client.
	#[must_use]
	pub fn new(pool: SharedAsyncStreamPool) -> Self {
		Self { pool }
	}

	/// Send raw bytes and wait for a response until the clients configured
	/// timeout.
	pub async fn call(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		// TODO: ales - remove later, debug reasons
		let pool = self.pool.read().await;
		let mut stream = pool.get().await;
		eprintln!("AsyncClient::call - Stream aquired");

		let resp = stream.call(request).await?;
		Ok(resp)
	}
}
