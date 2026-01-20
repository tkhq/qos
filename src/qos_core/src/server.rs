//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::sync::Arc;

use tokio::{
	sync::{OwnedSemaphorePermit, RwLock, Semaphore},
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

/// Alias to simplify `Arc<RwLock<P>>` where `P` is the `RequestProcessor`
pub type SharedProcessor<P> = Arc<RwLock<P>>;

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
	pub fn listen_all<P>(
		pool: StreamPool,
		processor: &SharedProcessor<P>,
		max_connections: usize,
	) -> Result<Self, SocketServerError>
	where
		P: RequestProcessor + Sync + 'static,
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

	fn spawn_tasks_for_listeners<P>(
		listeners: Vec<Listener>,
		processor: &SharedProcessor<P>,
		max_connections: usize,
	) -> Vec<JoinHandle<Result<(), SocketServerError>>>
	where
		P: RequestProcessor + Sync + 'static,
	{
		let mut tasks = Vec::new();
		for listener in listeners {
			let p = processor.clone();
			let task = tokio::spawn(async move {
				accept_loop(listener, p, max_connections).await
			});

			tasks.push(task);
		}

		tasks
	}

	/// Expand the server with listeners up to pool size. This adds new tasks as needed.
	pub fn listen_to<P>(
		&mut self,
		pool_size: u8,
		processor: &SharedProcessor<P>,
	) -> Result<(), IOError>
	where
		P: RequestProcessor + Sync + 'static,
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
	pub async fn accept(
		listener: &Listener,
		connections: Arc<Semaphore>,
	) -> Result<Self, IOError> {
		let _permit = connections
			.acquire_owned()
			.await
			.map_err(|_| IOError::UnknownError)?; // this really shouldn't happen since we never close the semaphore

		let stream = listener.accept().await?;

		Ok(PermittedStream { _permit, stream })
	}

	/// Perform a `Stream::send`
	pub async fn send(&mut self, value: &[u8]) -> Result<(), IOError> {
		self.stream.send(value).await
	}

	/// Perform a `Stream::recv`
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
	processor: SharedProcessor<P>,
	max_connections: usize,
) -> Result<(), SocketServerError>
where
	P: RequestProcessor + 'static,
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

		let p = processor.clone();
		tokio::spawn(async move {
			loop {
				match stream.recv().await {
					Ok(payload) => {
						let response = p.read().await.process(&payload).await;

						match stream.send(&response).await {
							Ok(()) => {}
							Err(err) => {
								eprintln!("SocketServer: error sending reply {err:?}, re-accepting");
								break;
							}
						}
					}
					Err(err) => match err {
						IOError::RecvConnectionClosed => break, // expected as we reconnect after each request currently
						_ => {
							eprintln!("SocketServer: error receiving request {err:?}, re-accepting");
							break;
						}
					},
				}
			}
		});
	}
}
