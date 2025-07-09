//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use tokio::task::JoinHandle;

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
pub struct AsyncSocketServer {
	/// `AsyncStreamPool` used to serve messages over.
	pub pool: AsyncStreamPool,
	/// List of tasks that are running on the server.
	pub tasks: Vec<JoinHandle<Result<(), SocketServerError>>>,
}

impl AsyncSocketServer {
	/// Listen and respond to incoming requests on all the pool's addresses with the given `processor`.
	/// This method returns a list of tasks that are running as part of this listener. `JoinHandle::abort()`
	/// should be called on each when the program exists (e.g. on ctrl+c)
	pub fn listen_all<P>(
		pool: AsyncStreamPool,
		processor: &P,
	) -> Result<Self, SocketServerError>
	where
		P: AsyncRequestProcessor + 'static + Clone,
	{
		println!("`AsyncSocketServer` listening on pool size {}", pool.len());

		let listeners = pool.listen()?;
		let tasks = Self::spawn_tasks_for_listeners(listeners, processor);

		Ok(Self { pool, tasks })
	}

	fn spawn_tasks_for_listeners<P>(
		listeners: Vec<AsyncListener>,
		processor: &P,
	) -> Vec<JoinHandle<Result<(), SocketServerError>>>
	where
		P: AsyncRequestProcessor + 'static + Clone,
	{
		let mut tasks = Vec::new();
		for listener in listeners {
			let p = processor.clone();
			let task =
				tokio::spawn(async move { accept_loop(listener, p).await });

			tasks.push(task);
		}

		tasks
	}

	/// Expand the server with listeners up to pool size. This adds new tasks as needed.
	pub fn listen_to<P>(
		&mut self,
		pool_size: u32,
		processor: &P,
	) -> Result<(), IOError>
	where
		P: AsyncRequestProcessor + 'static + Clone,
	{
		let listeners = self.pool.listen_to(pool_size)?;
		let tasks = Self::spawn_tasks_for_listeners(listeners, processor);

		self.tasks.extend(tasks);

		Ok(())
	}

	/// Consume the socket server and terminate all running tasks.
	pub fn terminate(self) {
		for task in self.tasks {
			task.abort();
		}
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
							eprintln!(
								"AsyncServer: unexpected eof, re-accepting"
							);
							break; // just re-accept
						}
					}
					_ => return Err(err.into()),
				},
			}
		}
	}
}
