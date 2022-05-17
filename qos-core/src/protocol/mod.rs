//! OS execution protocol.

mod attestor;
mod msg;
mod nitro_types;
mod provisioner;

pub use attestor::{MockNsm, Nsm, NsmProvider};
pub use msg::*;
pub use nitro_types::*;
use openssl::rsa::Rsa;
pub use provisioner::SECRET_FILE;
use provisioner::*;

use crate::server;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

pub struct ProtocolState {
	provisioner: SecretProvisioner,
	attestor: Box<dyn NsmProvider>,
}

impl ProtocolState {
	pub fn new(attestor: Box<dyn NsmProvider>) -> Self {
		let provisioner = SecretProvisioner::new();
		Self { attestor, provisioner }
	}
}

pub struct Executor {
	routes: Vec<Box<ProtocolHandler>>,
	state: ProtocolState,
}

impl Executor {
	pub fn new(attestor: Box<dyn NsmProvider>) -> Self {
		Self {
			routes: vec![
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm),
			],
			state: ProtocolState::new(attestor),
		}
	}
}

impl server::Routable for Executor {
	fn process(&mut self, mut req_bytes: Vec<u8>) -> Vec<u8> {
		use msg::Serialize as _;

		let msg_req = match ProtocolMsg::deserialize(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => return ProtocolMsg::ErrorResponse.serialize(),
		};

		for handler in self.routes.iter() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => return msg_resp.serialize(),
				None => continue,
			}
		}

		ProtocolMsg::ErrorResponse.serialize()
	}
}

mod handlers {
	use super::*;

	pub fn empty(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EmptyRequest = req {
			Some(ProtocolMsg::EmptyResponse)
		} else {
			None
		}
	}

	pub fn echo(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EchoRequest(e) = req {
			Some(ProtocolMsg::EchoResponse(e.clone()))
		} else {
			None
		}
	}

	pub fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProvisionRequest(pr) = req {
			match state.provisioner.add_share(pr.share.clone()) {
				Ok(_) => Some(ProtocolMsg::SuccessResponse),
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn reconstruct(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ReconstructRequest = req {
			match state.provisioner.reconstruct() {
				Ok(secret) => {
					state.provisioner.secret = Some(secret);
					Some(ProtocolMsg::SuccessResponse)
				}
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn nsm(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		// if let ProtocolMsg::NsmRequest(NsmRequest::Attestation { .. }) = req {
		if let ProtocolMsg::NsmRequest(_req) = req {
			let attestation = NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(
					Rsa::generate(4096).unwrap().public_key_to_pem().unwrap(),
				),
			};
			let fd = state.attestor.nsm_init();
			let response = state.attestor.nsm_process_request(fd, attestation);
			// match response {
			// 	NsmResponse::Attestation { ref document } => {
			// 		// use std::fs::File;
			// 		// use std::io::Write;
			// 		// let mut file =
			// 		// 	File::create("/home/tk/attest_document").unwrap();
			// 		// file.write_all(&document).unwrap();
			// 	}
			// 	_ => panic!("Not an attestation response"),
			// }
			println!("NSM process request: {:?}", response);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}
}
