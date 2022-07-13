//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::marker::PhantomData;

use crate::io::{self, Listener, SocketAddress};

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
pub trait Routable {
	/// Process an incoming request and return a response.
	///
	/// The request and response are raw bytes. Likely this should be encoded
	/// data and logic inside of this function should take care of decoding the
	/// request and encoding a response.
	fn process(&mut self, request: Vec<u8>) -> Vec<u8>;
}

/// A bare bare bones, socket based server.
pub struct SocketServer<R: Routable> {
	_phantom: PhantomData<R>,
}

impl<R: Routable> SocketServer<R> {
	/// Listen and respond to incoming requests with the given `processor`.
	pub fn listen(
		addr: SocketAddress,
		mut processor: R,
	) -> Result<(), SocketServerError> {
		println!("`SocketServer` listening on {:?}", addr);

		let listener = Listener::listen(addr)?;

		for stream in listener {
			match stream.recv() {
				Ok(payload) => {
					dbg!("calling processor");
					let response = processor.process(payload);
					let _ = stream.send(&response);
				}
				Err(err) => eprintln!("Server::listen error: {:?}", err),
			}
		}

		Ok(())
	}
}
