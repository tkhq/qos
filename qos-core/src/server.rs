//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::marker::PhantomData;

use crate::io::{self, threadpool::ThreadPool, Listener, SocketAddress};

const DEFAULT_THREAD_COUNT: usize = 4;

/// Error variants for [`SocketServer`]
#[derive(Debug)]
pub enum SocketServerError {
	/// `io::IOError` wrapper.
	IOError(io::IOError),
}

impl From<io::IOError> for SocketServerError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

/// Something that can process requests.
pub trait RequestProcessor {
	/// Process an incoming request and return a response.
	///
	/// The request and response are raw bytes. Likely this should be encoded
	/// data and logic inside of this function should take care of decoding the
	/// request and encoding a response.
	fn process(&mut self, request: Vec<u8>) -> Vec<u8>;
}

/// A bare bones, socket based server.
pub struct SocketServer<R: RequestProcessor> {
	_phantom: PhantomData<R>,
}

impl<R: RequestProcessor + Send + Sync + 'static + Clone> SocketServer<R> {
	/// Listen and respond to incoming requests with the given `processor`.
	///
	/// # Note Importantly
	///
	/// The `processor` must afford the ability to be cloned and passed to a new
	/// thread. For every new request, the `processor` will be cloned and passed
	/// to a new thread, so if it has any state that state needs to be thread
	/// safe after being cloned.
	#[allow(clippy::needless_pass_by_value)]
	pub fn listen(
		addr: SocketAddress,
		processor: R,
		thread_count: Option<usize>,
	) -> Result<(), SocketServerError> {
		let thread_count = thread_count.unwrap_or(DEFAULT_THREAD_COUNT);
		println!(
			"`SocketServer` listening on {:?} with thread count {thread_count}",
			addr
		);

		let listener = Listener::listen(addr)?;
		let thread_pool = ThreadPool::new(thread_count);

		for stream in listener {
			let processor2 = processor.clone();

			let _ = thread_pool
				.execute(move || Self::handle_stream(processor2, stream))
				.map_err(|e| eprintln!("`SocketServer::listen`: {:?}", e));
		}

		Ok(())
	}

	#[allow(clippy::needless_pass_by_value)]
	fn handle_stream(mut processor: R, stream: io::Stream) {
		match stream.recv() {
			Ok(payload) => {
				let response = processor.process(payload);
				let _ = stream.send(&response);
			}
			Err(err) => eprintln!("Server::listen error: {:?}", err),
		}
	}
}
