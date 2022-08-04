//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`crate::client::Client`].

use std::{marker::PhantomData};


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
		mut processor: R,
	) -> Result<(), SocketServerError> {
		println!("`SocketServer` listening on {:?}", addr);

		let listener = Listener::listen(addr)?;
		// let threads = Vec::new();
		// let proccesor_locked = Arc::new(Mutex::new(processor));

		// futures::executor::block_on(listener.for_each_concurrent(None,  move|stream| {
		// 	match stream.recv() {
		// 		Ok(payload) => {
		// 			let response = proccesor_locked.clone().lock().unwrap().process(payload);
		// 			// let _ = stream.send(&response);
		// 		}
		// 		Err(err) => eprintln!("Server::listen error: {:?}", err),
		// 	}
		// }));

		for stream in listener {
				match stream.recv() {
					Ok(payload) => {
						let response = processor.process(payload);
						let _ = stream.send(&response);
					}
					Err(err) => eprintln!("Server::listen error: {:?}", err),
				}
		}

		// for stream in listener {
		// 	// TODO: wait if threads are maxed out
		// 	let processor2 = processor.clone();
		// 	let thread = std::thread::spawn(move || {
		// 			match stream.recv() {
		// 				Ok(payload) => {
		// 					let response = processor.process(payload);
		// 					let _ = stream.send(&response);
		// 				}
		// 				Err(err) => eprintln!("Server::listen error: {:?}", err),
		// 			}
		// 		}
		// 	);
		// 	threads.push(thread);

		// }

		// for thread in threads {
		// 	drop(thread.join());
		// }

		Ok(())
	}
}
