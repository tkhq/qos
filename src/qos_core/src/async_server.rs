//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::marker::PhantomData;

use crate::{
	io::{AsyncListener, SocketAddress},
	server::SocketServerError,
};

/// Something that can process requests in an async way.
pub trait AsyncRequestProcessor {
	/// Process an incoming request and return a response in async.
	///
	/// The request and response are raw bytes. Likely this should be encoded
	/// data and logic inside of this function should take care of decoding the
	/// request and encoding a response.
	fn process(
		&mut self,
		request: Vec<u8>,
	) -> impl std::future::Future<Output = Vec<u8>>;
}

/// A bare bones, socket based server.
pub struct AsyncSocketServer<R: AsyncRequestProcessor> {
	_phantom: PhantomData<R>,
}

impl<R: AsyncRequestProcessor> AsyncSocketServer<R> {
	/// Listen and respond to incoming requests with the given `processor`.
	pub async fn listen(
		addr: SocketAddress,
		mut processor: R,
	) -> Result<(), SocketServerError> {
		println!("`SocketServer` listening on {addr:?}");

		let listener = AsyncListener::listen(addr).await?;

		loop {
			let mut stream = listener.accept().await?;
			match stream.recv().await {
				Ok(payload) => {
					let response = processor.process(payload).await;
					let _ = stream.send(&response).await?;
				}
				Err(err) => eprintln!("AsyncServer::listen error: {err:?}"),
			}
		}
	}
}
