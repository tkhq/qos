//! Streaming socket based server for use in an enclave. Listens for connections
//! from [`client::Client`].

use std::{collections::BTreeSet, fs::File, io::Write, marker::PhantomData};

use aws_nitro_enclaves_nsm_api as nsm;
use qos_crypto;

use crate::{
	io,
	io::{Listener, SocketAddress, Stream},
	protocol::{self, ProtocolError, ProtocolMsg, ProvisionRequest, Serialize},
};

#[derive(Debug)]
pub enum SocketServerError {
	IOError(io::IOError),
	ProtocolError(protocol::ProtocolError),
	NotFound,
}

impl From<io::IOError> for SocketServerError {
	fn from(err: io::IOError) -> Self {
		Self::IOError(err)
	}
}

impl From<protocol::ProtocolError> for SocketServerError {
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
	fn add_share(&mut self, share: Share) -> Result<(), SocketServerError> {
		if share.len() == 0 {
			return Err(SocketServerError::ProtocolError(
				ProtocolError::InvalidShare,
			));
		}

		self.shares.push(share);
		Ok(())
	}

	fn reconstruct(&mut self) -> Result<Secret, SocketServerError> {
		let secret = qos_crypto::shares_reconstruct(&self.shares);

		// TODO: Add better validation...
		if secret.len() == 0 {
			return Err(SocketServerError::ProtocolError(
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
	fn nsm_process_request(
		&self,
		fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response;

	/// See [`aws_nitro_enclaves_nsm_api::driver::nsm_init`]
	fn nsm_init(&self) -> i32;

	/// See [`aws_nitro_enclaves_nsm_api::driver::nsm_exit`]
	fn nsm_exit(&self, fd: i32);
}

/// TODO - this should be moved to its own crate as it will likely need some
/// additional deps like Serde
pub struct MockNsm {}

impl NsmProvider for MockNsm {
	fn nsm_process_request(
		&self,
		_fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response {
		use nsm::api::{Request as Req, Response as Resp};
		println!("MockNsm::process_request request={:?}", request);
		match request {
			Req::Attestation { user_data: _, nonce: _, public_key: _ } => {
				// TODO: this should be a CBOR-encoded AttestationDocument as
				// the payload
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

	fn nsm_init(&self) -> i32 {
		33
	}

	fn nsm_exit(&self, fd: i32) {
		// Should be hardcoded to value returned by nsm_init
		assert_eq!(fd, 33);
		println!("nsm_exit");
	}
}

type Secret = Vec<u8>;
pub struct SocketServer<N: NsmProvider> {
	provisioner: Provisioner,
	secret: Option<Secret>,
	_phantom: PhantomData<N>,
}

impl<N: NsmProvider> SocketServer<N> {
	pub fn listen(addr: SocketAddress) -> Result<(), SocketServerError> {
		let mut server = SocketServer {
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
						let _ = stream.send(&res).map_err(|e| {
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						let _ = stream.send(&res).map_err(|e| {
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
						let _ = stream.send(&res).map_err(|e| {
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
					Err(_) => {
						let res = ProtocolMsg::ErrorResponse.serialize();
						let _ = stream.send(&res).map_err(|e| {
							// TODO: make eprint_and_ignore_err macro
							eprintln!("enclave::server::response: {:?}", e)
						});
					}
				}
			}
			Ok(ProtocolMsg::NsmRequest(nsm_request)) => {
				let fd = N::nsm_init();
				let response = N::nsm_process_request(fd, nsm_request);
				N::nsm_exit(fd);

				let res = ProtocolMsg::NsmResponse(response).serialize();
				let _ = stream.send(&res);
			}
			Err(e) => {
				eprintln!("Server::respond error: unknown request: {:?}", e);
			}
			_ => unimplemented!(),
		};
	}
}

trait ReqProcessor<S> {
	fn process_req(
		&self,
		req: Vec<u8>,
		state: S,
	) -> Result<Vec<u8>, SocketServerError>;
}

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

struct Router {
	routes: Vec<Box<ProtocolHandler>>,
}

impl Router {
	fn new() -> Self {
		Self { routes: Vec::new() }
	}

	/// Mounter a `ProtocolHandler`.
	fn mount(mut self, f: Box<ProtocolHandler>) -> Self {
		self.routes.push(f);
		self
	}
}

struct ProtocolState {
	provisioner: Provisioner,
	secret: Option<Secret>,
	// TODO make this gneric over NsmProvider
	attestor: MockNsm,
}

impl ReqProcessor<ProtocolState> for Router {
	fn process_req(
		&self,
		mut req_bytes: Vec<u8>,
		state: ProtocolState,
	) -> Result<Vec<u8>, SocketServerError> {
		use protocol::Serialize as _;

		let mut msg_req = match ProtocolMsg::deserialize(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => return Ok(ProtocolMsg::ErrorResponse.serialize()),
		};

		// outer scope
		for handler in self.routes.iter() {
			match handler(&msg_req, &mut state) {
				Some(msg_resp) => return Ok(msg_resp.serialize()),
				None => continue,
			}
		}

		Err(SocketServerError::NotFound)
	}
}

mod handlers {
	use super::*;

	pub(super) fn empty(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EmptyRequest = req {
			Some(ProtocolMsg::EmptyResponse)
		} else {
			None
		}
	}

	pub(super) fn echo(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EchoRequest(e) = req {
			Some(ProtocolMsg::EchoResponse(e.clone()))
		} else {
			None
		}
	}

	pub(super) fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProvisionRequest(pr) = req {
			match state.provisioner.add_share(pr.share) {
				Ok(_) => Some(ProtocolMsg::SuccessResponse),
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub(super) fn reconstruct(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ReconstructRequest = req {
			match state.provisioner.reconstruct() {
				Ok(secret) => {
					state.secret = Some(secret);
					Some(ProtocolMsg::SuccessResponse)
				}
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub(super) fn nsm(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest(_nsmr) = req {
			let fd = state.attestor.nsm_init();
			let response = state
				.attestor
				.nsm_process_request(fd, nsm::api::Request::DescribeNSM);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}
}
