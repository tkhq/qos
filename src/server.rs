use crate::io;
use crate::io::stream::SocketAddress;
use crate::io::stream::{Listener, Stream};
use crate::protocol::{self, ProtocolRequest, Serialize};

#[derive(Debug)]
pub enum ServerError {
	IOError(io::IOError),
	UnknownError,
	ProtocolError(protocol::ProtocolError),
}

impl From<io::IOError> for ServerError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<protocol::ProtocolError> for ServerError {
	fn from(err: protocol::ProtocolError) -> Self {
		Self::ProtocolError(err)
	}
}

pub struct Server {
	// listener: Listener,
}

impl Server {
	pub fn listen(addr: SocketAddress) -> Result<(), ServerError> {
		let mut listener = Listener::listen(addr)?;
		while let Some(stream) = listener.next() {
			match stream.recv() {
				Ok(payload) => Self::respond(stream, payload),
				Err(err) => println!("Received error: {:?}", err),
			}
		}

		Ok(())
	}

	fn respond(stream: Stream, mut payload: Vec<u8>) {
		let request = ProtocolRequest::deserialize(&mut payload);

		let result: Result<(), ServerError> = match request {
			Ok(ProtocolRequest::Empty) => {
				println!("Empty request...");
				let res = b"Empty!".to_vec();
				stream.send(&res).map_err(Into::into)
			}
			Ok(ProtocolRequest::Echo(e)) => {
				println!("Received echo...");
				let res = e.serialize();
				stream.send(&res).map_err(Into::into)
			}
			Err(e) => {
				println!("Unknown request...");
				Err(e.into())
			}
		};

		println!("respond result: {:?}", result);
	}
}
