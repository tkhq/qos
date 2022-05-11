//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use crate::{
	io,
	io::{Listener, SocketAddress, Stream},
};
use std::marker::PhantomData;

#[derive(Debug)]
pub enum SocketServerError {
	IOError(io::IOError),
	NotFound,
}

impl From<io::IOError> for SocketServerError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

pub struct SocketServer<R: Routable<S>, S> {
	_phantom: PhantomData<(R, S)>,
}

impl<R: Routable<S>, S> SocketServer<R, S> {
	pub fn listen(
		addr: SocketAddress,
		processor: R,
		mut state: S,
	) -> Result<(), SocketServerError> {
		let mut listener = Listener::listen(addr)?;
		while let Some(stream) = listener.next() {
			match stream.recv() {
				Ok(payload) => {
					let response = processor.process(payload, &mut state);
					let _ = stream.send(&response);
				}
				Err(err) => eprintln!("Server::listen error: {:?}", err),
			}
		}

		Ok(())
	}
}

pub trait Routable<S> {
	fn process(&self, req: Vec<u8>, state: &mut S) -> Vec<u8>;
}
