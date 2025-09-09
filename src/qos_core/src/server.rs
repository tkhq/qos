//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::sync::Arc;

use tokio::{sync::RwLock, task::JoinHandle};

use crate::io::{IOError, Listener, StreamPool};

/// Error variants for [`SocketServer`]
#[derive(Debug)]
pub enum SocketServerError {
	/// `io::IOError` wrapper.
	IOError(IOError),
}

impl From<IOError> for SocketServerError {
	fn from(err: IOError) -> Self {
		Self::IOError(err)
	}
}

/// Alias to simplify `Arc<RwLock<P>>` where `P` is the `RequestProcessor`
pub type SharedProcessor<P> = Arc<RwLock<P>>;

/// Something that can process requests in an async way.
pub trait RequestProcessor: Send {
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
}

impl SocketServer {
	/// Listen and respond to incoming requests on all the pool's addresses with the given `processor`.
	/// This method returns `SocketServer` which contains all the handles for running tasks.
	/// `terminate` should be called on the server when execution is to be finished (e.g. ctrl+c handling)
	pub fn listen_all<P>(
		pool: StreamPool,
		processor: &SharedProcessor<P>,
	) -> Result<Self, SocketServerError>
	where
		P: RequestProcessor + Sync + 'static,
	{
		println!("`SocketServer` listening on pool size {}", pool.len());

		let listeners = pool.listen()?;
		let tasks = Self::spawn_tasks_for_listeners(listeners, processor);

		Ok(Self { pool, tasks })
	}

	fn spawn_tasks_for_listeners<P>(
		listeners: Vec<Listener>,
		processor: &SharedProcessor<P>,
	) -> Vec<JoinHandle<Result<(), SocketServerError>>>
	where
		P: RequestProcessor + Sync + 'static,
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
		processor: &SharedProcessor<P>,
	) -> Result<(), IOError>
	where
		P: RequestProcessor + Sync + 'static,
	{
		let listeners = self.pool.listen_to(pool_size)?;
		let tasks = Self::spawn_tasks_for_listeners(listeners, processor);

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

async fn accept_loop<P>(
	listener: Listener,
	processor: SharedProcessor<P>,
) -> Result<(), SocketServerError>
where
	P: RequestProcessor,
{
	loop {
		let mut stream = match listener.accept().await {
			Ok(stream) => stream,
			Err(err) => {
				eprintln!("SocketServer: error on accept {err:?}");
				continue;
			}
		};

		loop {
			match stream.recv().await {
				Ok(payload) => {
					let response =
						processor.read().await.process(&payload).await;

					match stream.send(&response).await {
						Ok(()) => {}
						Err(err) => {
							eprintln!("SocketServer: error sending reply {err:?}, re-accepting");
							break;
						}
					}
				}
				Err(err) => {
					eprintln!("SocketServer: error receiving request {err:?}, re-accepting");
					break;
				}
			}
		}
	}
}
