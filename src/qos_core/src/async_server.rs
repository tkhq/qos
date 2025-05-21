//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::marker::PhantomData;

use crate::{
	io::{AsyncListener, AsyncStreamPool, IOError},
	server::SocketServerError,
};

/// Something that can process requests in an async way.
pub trait AsyncRequestProcessor: Send {
	/// Process an incoming request and return a response in async.
	///
	/// The request and response are raw bytes. Likely this should be encoded
	/// data and logic inside of this function should take care of decoding the
	/// request and encoding a response.
	fn process(
		&self,
		request: Vec<u8>,
	) -> impl std::future::Future<Output = Vec<u8>> + Send;
}

/// A bare bones, socket based server.
pub struct AsyncSocketServer<R: AsyncRequestProcessor> {
	_phantom: PhantomData<R>,
}

impl<R> AsyncSocketServer<R>
where
	R: AsyncRequestProcessor + 'static + Clone,
{
	/// Listen and respond to incoming requests on all the pool's addresses with the given `processor`.
	/// *NOTE*: the `POOL_SIZE` must match on both sides, since we expect ALL sockets to be connected
	/// to right away (e.g. not on first use). The client side connect (above) will always connect them all.
	pub async fn listen_all(
		pool: AsyncStreamPool,
		processor: R,
	) -> Result<(), SocketServerError> {
		println!("`AsyncSocketServer` listening on pool"); // TODO: ales - add the addresses here

		let listeners = pool.listen()?;

		let mut tasks = Vec::new();
		for listener in listeners {
			let p = processor.clone();
			let task =
				tokio::spawn(async move { accept_loop(listener, p).await });

			tasks.push(task);
		}

		// wait for ALL pool connections
		let joined = futures::future::join_all(tasks).await;
		for outer_result in joined {
			match outer_result {
				Err(_join_err) => {
					return Err(SocketServerError::IOError(
						crate::io::IOError::UnknownError, // TODO: add a join error translation to IOError
					));
				} // this really shouldn't happen
				Ok(result) => result?,
			}
		}

		Ok(())
	}
}

async fn accept_loop<P>(
	listener: AsyncListener,
	processor: P,
) -> Result<(), SocketServerError>
where
	P: AsyncRequestProcessor + Clone,
{
	loop {
		let mut stream = listener.accept().await?;
		loop {
			match stream.recv().await {
				Ok(payload) => {
					let response = processor.process(payload).await;
					stream.send(&response).await?;
				}
				Err(err) => match err {
					IOError::StdIoError(err) => {
						if err.kind() == std::io::ErrorKind::UnexpectedEof {
							break; // just re-accept
						}
					}
					_ => return Err(err.into()),
				},
			}
		}
	}
}
