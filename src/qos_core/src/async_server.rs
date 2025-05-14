//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::{marker::PhantomData, sync::Arc};

use tokio::sync::Mutex;

use crate::{
	io::{AsyncListener, AsyncStreamPool, SocketAddress},
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
		&mut self,
		request: Vec<u8>,
	) -> impl std::future::Future<Output = Vec<u8>> + Send;
}

/// A bare bones, socket based server.
pub struct AsyncSocketServer<R: AsyncRequestProcessor> {
	_phantom: PhantomData<R>,
}

impl<R: AsyncRequestProcessor + 'static> AsyncSocketServer<R> {
	/// Listen and respond to incoming requests with the given `processor`.
	pub async fn listen(
		addr: SocketAddress,
		mut processor: R,
	) -> Result<(), SocketServerError> {
		println!("`AsyncSocketServer` listening on {addr:?}");

		let listener = AsyncListener::listen(addr).await?;

		loop {
			let mut stream = listener.accept().await?;
			loop {
				match stream.recv().await {
					Ok(payload) => {
						let response = processor.process(payload).await;
						let _ = stream.send(&response).await?;
					}
					Err(err) => {
						eprintln!("AsyncServer::listen error: {err:?}");
						break;
					}
				}
			}
		}
	}

	/// Listen and respond to incoming requests on all the pool's addresses with the given `processor`.
	pub async fn listen_all(
		pool: AsyncStreamPool,
		processor: R,
	) -> Result<(), SocketServerError> {
		println!("`AsyncSocketServer` listening on pool"); // TODO: add the addresses herei

		let listeners = pool.listen().await?;
		let processor = Arc::new(Mutex::new(processor));

		let mut tasks = Vec::new();
		for listener in listeners {
			let p = processor.clone();
			let task =
				tokio::spawn(async move { accept_loop(listener, p).await });

			tasks.push(task);
		}

		// TODO: should be select_all
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
	processor: Arc<Mutex<P>>,
) -> Result<(), SocketServerError>
where
	P: AsyncRequestProcessor,
{
	loop {
		let mut stream = listener.accept().await?;
		loop {
			match stream.recv().await {
				Ok(payload) => {
					// TODO: check if we need to lock until AFTER response
					let mut p = processor.lock().await;
					let response = p.process(payload).await;
					let _ = stream.send(&response).await?;
				}
				Err(err) => return Err(SocketServerError::IOError(err)),
			}
		}
	}
}
