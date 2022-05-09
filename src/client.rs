use crate::{
	io::{self, SocketAddress, Stream},
	protocol::{ProtocolError, ProtocolRequest, Serialize},
};

#[derive(Debug)]
pub enum ClientError {
	IOError(io::IOError),
	ProtocolError(ProtocolError),
}

impl From<io::IOError> for ClientError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<ProtocolError> for ClientError {
	fn from(err: ProtocolError) -> Self {
		Self::ProtocolError(err)
	}
}

pub struct Client {
	addr: SocketAddress,
}

impl Client {
	pub fn new(addr: SocketAddress) -> Self {
		Self { addr }
	}

	pub fn send(
		&self,
		request: ProtocolRequest,
	) -> Result<ProtocolRequest, ClientError> {
		let stream = Stream::connect(&self.addr)?;
		stream.send(&request.serialize())?;
		let mut response = stream.recv()?;
		ProtocolRequest::deserialize(&mut response).map_err(Into::into)
	}
}
