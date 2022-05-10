//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use crate::{
	io,
	io::{Listener, SocketAddress, Stream},
	protocol::{
		self, NsmRequest, ProtocolError, ProtocolMsg, ProvisionRequest,
		Serialize,
	},
};
use aws_nitro_enclaves_nsm_api as nsm;
use qos_crypto;
use std::{collections::BTreeSet, fs::File};
use std::{io::Write, marker::PhantomData};

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

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

pub trait NsmProvider {
	/// See [`aws_nitro_enclaves_nsm_api::driver::process_request`]
	fn process_request(
		fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response;

	/// See [`aws_nitro_enclaves_nsm_api::driver::nsm_init`]
	fn nsm_init() -> i32;

	/// See [`aws_nitro_enclaves_nsm_api::driver::nsm_exit`]
	fn nsm_exit(fd: i32);
}

/// TODO - this should be moved to its own crate as it will likely need some additional deps
/// like Serde
pub struct MockNsm {}

impl NsmProvider for MockNsm {
	fn process_request(
		_fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response {
		use nsm::api::{Request as Req, Response as Resp};
		println!("MockNsm::process_request request={:?}", request);
		match request {
			Req::Attestation { user_data: _, nonce: _, public_key: _ } => {
				// TODO: this should be a CBOR-encoded AttestationDocument as the payload
				Resp::Attestation { document: Vec::new() }
			}
			Req::DescribeNSM => Resp::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: "mock_module_id".to_string(),
				max_pcrs: 1024,
				locked_pcrs: BTreeSet::from([90, 91, 92]),
				digest: nsm::api::Digest::SHA256,
			},
			Req::ExtendPCR { index: _, data: _ } => {
				Resp::ExtendPCR { data: vec![3, 4, 7, 4] }
			}
			Req::GetRandom => Resp::GetRandom { random: vec![4, 2, 0, 69] },
			Req::LockPCR { index: _ } => Resp::LockPCR,
			Req::LockPCRs { range: _ } => Resp::LockPCRs,
			Req::DescribePCR { index: _ } => {
				Resp::DescribePCR { lock: false, data: vec![3, 4, 7, 4] }
			}
			_ => Resp::Error(nsm::api::ErrorCode::InternalError),
		}
	}

	fn nsm_init() -> i32 {
		33
	}

	fn nsm_exit(fd: i32) {
		// Should be hardcoded to value returned by nsm_int
		assert_eq!(fd, 33);
		println!("nsm_exit");
	}
}

type Secret = Vec<u8>;
pub struct Server<N: NsmProvider> {
	provisioner: Provisioner,
	secret: Option<Secret>,
	nsm: N,
}

impl<N: NsmProvider> Server<N> {
	pub fn listen(addr: SocketAddress) -> Result<(), ServerError> {
		let mut server = Server {
			provisioner: Provisioner { shares: Shares::new() },
			secret: None,
			_phantom: PhantomData::<N>,
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
						let _ = stream.send(&res).map(|e| {
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						let _ = stream.send(&res).map(|e| {
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
				}
			}
			Ok(ProtocolMsg::ReconstructRequest) => {
				match self.provisioner.reconstruct() {
					Ok(secret) => {
						self.secret = Some(secret);
						let res = ProtocolMsg::SuccessResponse.serialize();
						let _ = stream.send(&res).map(|e| {
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						let _ = stream.send(&res).map(|e| {
							// TODO: make eprint_and_ignore_err macro
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
				}
			}
			Ok(ProtocolMsg::NsmRequest(NsmRequest { data: _ })) => {
				let fd = <Self::N as NsmProvider>::nsm_init();

				<Self::N as NsmProvider>::process_request
			}
			Err(e) => {
				eprintln!("Server::respond error: unknown request: {:?}", e);
			}
			_ => unimplemented!(),
		};
	}
}
