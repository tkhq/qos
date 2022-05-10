//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use crate::{
	io,
	io::{Listener, SocketAddress, Stream},
	protocol::{self, ProtocolMsg, Serialize},
};

#[derive(Debug)]
pub enum ServerError {
	IOError(io::IOError),
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

pub struct Server {}

impl Server {
	pub fn listen(addr: SocketAddress) -> Result<(), ServerError> {
		let mut listener = Listener::listen(addr)?;
		while let Some(stream) = listener.next() {
			match stream.recv() {
				Ok(payload) => Self::respond(stream, payload),
				Err(err) => eprintln!("Server::listen error: {:?}", err),
			}
		}

		Ok(())
	}

	fn respond(stream: Stream, mut payload: Vec<u8>) {
		let request = ProtocolMsg::deserialize(&mut payload);

		match request {
			Ok(ProtocolMsg::EmptyRequest) => {
				println!("Empty request...");
				let res = b"Empty!".to_vec();
				let _ = stream.send(&res);
			}
			Ok(ProtocolMsg::EchoRequest(e)) => {
				println!("Received echo...");
				let res = ProtocolMsg::EchoRequest(e).serialize();
				let _ = stream.send(&res);
			}
			Err(e) => {
				eprintln!("Server::respond error: unknown request: {:?}", e);
			}
			_ => unimplemented!(),
		};
	}
}
