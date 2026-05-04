//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::{future::Future, ops::Deref, sync::Arc};

use tokio::{
	sync::{OwnedSemaphorePermit, Semaphore},
	task::JoinHandle,
};

use crate::io::{IOError, Listener, Stream, StreamPool};

/// Error variants for [`SocketServer`]
#[derive(Debug)]
pub enum SocketServerError {
	/// `io::IOError` wrapper.
	IOError(IOError),
	/// invalid pool configuration
	PoolInvalid,
}

impl From<IOError> for SocketServerError {
	fn from(err: IOError) -> Self {
		Self::IOError(err)
	}
}

/// Something that can process requests in an async way.
pub trait RequestProcessor: Send + Sync {
	/// Process an incoming request and return a response in async.
	///
	/// The request and response are raw bytes. Likely this should be encoded
	/// data and logic inside of this function should take care of decoding the
	/// request and encoding a response.
	fn process(
		&self,
		request: &[u8],
	) -> impl std::future::Future<Output = Vec<u8>> + Send;
}

impl<T, U> RequestProcessor for T
where
	T: Deref<Target = U> + Send + Sync,
	U: RequestProcessor + 'static,
{
	fn process(&self, request: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
		self.deref().process(request)
	}
}

/// A bare bones, socket based server.
pub struct SocketServer {
	/// `StreamPool` used to serve messages over.
	pub pool: StreamPool,
	/// List of tasks that are running on the server.
	pub tasks: Vec<JoinHandle<Result<(), SocketServerError>>>,
	/// Max connections set during creation, used for `listen_to` calls
	pub max_connections: usize,
}

impl SocketServer {
	/// Listen and respond to incoming requests on all the pool's addresses with the given `processor`.
	/// This method returns `SocketServer` which contains all the handles for running tasks.
	/// `terminate` should be called on the server when execution is to be finished (e.g. ctrl+c handling)
	/// The `max_connections` attribute limits how many accepted connections and running tasks can be handled concurrently
	/// per each pool address.
	///
	/// # Errors
	///
	/// Returns [`SocketServerError`] if the pool fails to bind listeners.
	pub fn listen_all<P>(
		pool: StreamPool,
		processor: P,
		max_connections: usize,
	) -> Result<Self, SocketServerError>
	where
		P: RequestProcessor + Clone + 'static,
	{
		println!("`SocketServer` listening on pool size {}", pool.len());

		let listeners = pool.listen()?;
		let tasks = Self::spawn_tasks_for_listeners(
			listeners,
			processor,
			max_connections,
		);

		Ok(Self { pool, tasks, max_connections })
	}

	/// Expand the server with listeners up to pool size. This adds new tasks as needed.
	///
	/// # Errors
	///
	/// Returns [`IOError`] if new listeners cannot be bound.
	pub fn listen_to<P>(
		&mut self,
		pool_size: u8,
		processor: P,
	) -> Result<(), IOError>
	where
		P: RequestProcessor + Clone + 'static,
	{
		let listeners = self.pool.listen_to(pool_size)?;
		let tasks = Self::spawn_tasks_for_listeners(
			listeners,
			processor,
			self.max_connections,
		);

		self.tasks.extend(tasks);

		Ok(())
	}

	fn spawn_tasks_for_listeners<P>(
		listeners: Vec<Listener>,
		processor: P,
		max_connections: usize,
	) -> Vec<JoinHandle<Result<(), SocketServerError>>>
	where
		P: RequestProcessor + Clone + 'static,
	{
		let mut tasks = Vec::new();
		for listener in listeners {
			let p = processor.clone();
			let task = tokio::spawn(async move {
				accept_loop(listener, &p, max_connections).await
			});

			tasks.push(task);
		}

		tasks
	}
}

impl Drop for SocketServer {
	fn drop(&mut self) {
		for task in &self.tasks {
			task.abort();
		}
	}
}

/// Used to ensure we drop `Stream` permits as tasks exit for any reason
pub struct PermittedStream {
	_permit: OwnedSemaphorePermit,
	stream: Stream,
}

impl PermittedStream {
	/// Accept a connection from the listener, acquiring a permit from the
	/// semaphore.
	///
	/// # Errors
	///
	/// Returns [`IOError`] if the permit cannot be acquired or the
	/// connection cannot be accepted.
	pub async fn accept(
		listener: &Listener,
		connections: Arc<Semaphore>,
	) -> Result<Self, IOError> {
		let permit = connections
			.acquire_owned()
			.await
			.map_err(|_| IOError::UnknownError)?; // this really shouldn't happen since we never close the semaphore

		let stream = listener.accept().await?;

		Ok(PermittedStream { _permit: permit, stream })
	}

	/// Perform a `Stream::send`.
	///
	/// # Errors
	///
	/// Returns [`IOError`] if the send fails.
	pub async fn send(&mut self, value: &[u8]) -> Result<(), IOError> {
		self.stream.send(value).await
	}

	/// Perform a `Stream::recv`.
	///
	/// # Errors
	///
	/// Returns [`IOError`] if the receive fails.
	pub async fn recv(&mut self) -> Result<Vec<u8>, IOError> {
		self.stream.recv().await
	}

	/// Mutable access to the underlaying `Stream`
	pub fn stream(&mut self) -> &mut Stream {
		&mut self.stream
	}
}

async fn accept_loop<P>(
	listener: Listener,
	processor: &P,
	max_connections: usize,
) -> Result<(), SocketServerError>
where
	P: RequestProcessor + Clone + 'static,
{
	let connections = Arc::new(Semaphore::const_new(max_connections));
	loop {
		let mut stream =
			match PermittedStream::accept(&listener, connections.clone()).await
			{
				Ok(stream) => stream,
				Err(err) => {
					eprintln!("SocketServer: error on accept {err:?}");
					continue;
				}
			};

		let processor = processor.clone();

		tokio::spawn(async move {
			loop {
				match stream.recv().await {
					Ok(payload) => {
						let response = processor.process(&payload).await;

						match stream.send(&response).await {
							Ok(()) => {}
							Err(err) => {
								eprintln!("SocketServer: error sending reply {err:?}, re-accepting");
								break;
							}
						}
					}
					Err(IOError::RecvConnectionClosed) => break,
					Err(err) => {
						eprintln!("SocketServer: error receiving request {err:?}, re-accepting");
						break;
					}
				}
			}
		});
	}
}
