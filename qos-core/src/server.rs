//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::{marker::PhantomData, sync::Arc};

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

impl<R: RequestProcessor> SocketServer<R> {
	/// Listen and respond to incoming requests with the given `processor`.
	pub fn listen(
		addr: SocketAddress,
		mut processor: Arc<R>,
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

			let result = thread_pool
				.execute(move || Self::handle_stream(processor2, stream))
				.map_err(|e| eprintln!("`SocketServer::listen`: {:?}", e));

			drop(result)
		}

		Ok(())
	}

	fn handle_stream(processor: Arc<R>, stream: io::Stream) {
		match stream.recv() {
			Ok(payload) => {
				let response = processor.process(payload);
				let _ = stream.send(&response);
			}
			Err(err) => eprintln!("Server::listen error: {:?}", err),
		}
	}
}
