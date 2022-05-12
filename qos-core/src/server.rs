//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use std::marker::PhantomData;

use crate::{
	io,
	io::{Listener, SocketAddress},
};

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

pub struct SocketServer<R: Routable> {
	_phantom: PhantomData<R>,
}

impl<R: Routable> SocketServer<R> {
	pub fn listen(
		addr: SocketAddress,
		mut processor: R,
	) -> Result<(), SocketServerError> {
		println!("SocketServer listening on {:?}", addr);

		let mut listener = Listener::listen(addr)?;

		while let Some(stream) = listener.next() {
			match stream.recv() {
				Ok(payload) => {
					let response = processor.process(payload);
					let _ = stream.send(&response);
				}
				Err(err) => eprintln!("Server::listen error: {:?}", err),
			}
		}

		Ok(())
	}
}

pub trait Routable {
	fn process(&mut self, req: Vec<u8>) -> Vec<u8>;
}
