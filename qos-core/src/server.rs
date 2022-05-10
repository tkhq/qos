//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use crate::{
	io,
	io::{Listener, SocketAddress, Stream},
	protocol::{self, ProtocolError, ProtocolMsg, ProvisionRequest, Serialize},
};
use qos_crypto;
use std::fs::File;
use std::io::Write;

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

pub const SECRET_FILE: &str = "./qos.key";

type Share = Vec<u8>;
type Shares = Vec<Share>;

struct Provisioner {
	shares: Shares,
}

impl Provisioner {
	fn add_share(&mut self, share: Share) -> Result<(), ServerError> {
		if share.len() == 0 {
			return Err(ServerError::ProtocolError(
				ProtocolError::InvalidShare,
			));
		}

		self.shares.push(share);
		Ok(())
	}

	fn reconstruct(&mut self) -> Result<Secret, ServerError> {
		let secret = qos_crypto::shares_reconstruct(&self.shares);

		// TODO: Add better validation...
		if secret.len() == 0 {
			return Err(ServerError::ProtocolError(
				ProtocolError::ReconstructionError,
			));
		}

		// TODO: Make errors more specific...
		let mut file = File::create(SECRET_FILE)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		file.write_all(&secret)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		Ok(secret)
	}
}

type Secret = Vec<u8>;
pub struct Server {
	provisioner: Provisioner,
	secret: Option<Secret>,
}

impl Server {
	pub fn listen(addr: SocketAddress) -> Result<(), ServerError> {
		let mut server = Server {
			provisioner: Provisioner { shares: Shares::new() },
			secret: None,
		};

		let mut listener = Listener::listen(addr)?;
		while let Some(stream) = listener.next() {
			match stream.recv() {
				Ok(payload) => server.respond(stream, payload),
				Err(err) => eprintln!("Server::listen error: {:?}", err),
			}
		}

		Ok(())
	}

	fn respond(&mut self, stream: Stream, mut payload: Vec<u8>) {
		let request = ProtocolMsg::deserialize(&mut payload);

		match request {
			Ok(ProtocolMsg::EmptyRequest) => {
				println!("Empty request...");
				let res = b"Empty!".to_vec();
				let _ = stream.send(&res);
			}
			Ok(ProtocolMsg::EchoRequest(e)) => {
				println!("Received echo...");
				let res = ProtocolMsg::EchoResponse(e).serialize();
				let _ = stream.send(&res);
			}
			Ok(ProtocolMsg::ProvisionRequest(ProvisionRequest { share })) => {
				match self.provisioner.add_share(share) {
					Ok(_) => {
						let res = ProtocolMsg::SuccessResponse.serialize();
						stream.send(&res);
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						stream.send(&res);
					}
				}
			}
			Ok(ProtocolMsg::ReconstructRequest) => {
				match self.provisioner.reconstruct() {
					Ok(secret) => {
						self.secret = Some(secret);
						let res = ProtocolMsg::SuccessResponse.serialize();
						stream.send(&res);
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						stream.send(&res);
					}
				}
			}
			Err(e) => {
				eprintln!("Server::respond error: unknown request: {:?}", e);
			}
			_ => unimplemented!(),
		};
	}
}
