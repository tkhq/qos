//! OS execution protocol.

mod attestor;
mod msg;
mod provisioner;

pub use attestor::{MockNsm, Nsm, NsmProvider, MOCK_NSM_ATTESTATION_DOCUMENT};
pub use msg::*;
use openssl::rsa::Rsa;
use provisioner::*;

use crate::server;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

pub struct ProtocolState {
	provisioner: SecretProvisioner,
	attestor: Box<dyn NsmProvider>,
	pivot_file: String,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
	) -> Self {
		let provisioner = SecretProvisioner::new(secret_file);
		Self { attestor, provisioner, pivot_file }
	}
}

pub struct Executor {
	routes: Vec<Box<ProtocolHandler>>,
	state: ProtocolState,
}

impl Executor {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
	) -> Self {
		Self {
			routes: vec![
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm_attestation),
				Box::new(handlers::load),
			],
			state: ProtocolState::new(attestor, secret_file, pivot_file),
		}
	}
}

impl server::Routable for Executor {
	fn process(&mut self, mut req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
				.expect("ProtocolMsg can always be serialized. qed.")
		}

		let msg_req = match serde_cbor::from_slice(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => {
				return serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
					.expect("ProtocolMsg can always be serialized. qed.")
			}
		};

		for handler in self.routes.iter() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => {
					return serde_cbor::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
			.expect("ProtocolMsg can always be serialized. qed.")
	}
}

mod handlers {
	use serde_bytes::ByteBuf;

	use super::*;

	macro_rules! ok_or_return {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return Some(ProtocolMsg::ErrorResponse),
			}
		};
	}

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

	pub fn nsm_attestation(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest(NsmRequest::Attestation { .. }) = req {
			let request = NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(ByteBuf::from(
					Rsa::generate(4096).unwrap().public_key_to_pem().unwrap(),
				)),
			};
			let fd = state.attestor.nsm_init();
			let response = state.attestor.nsm_process_request(fd, request);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}

	pub fn load(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::LoadRequest(Load { executable, signatures: _ }) =
			req
		{
			use std::{
				fs::{set_permissions, Permissions},
				os::unix::fs::PermissionsExt,
			};
			// for SignatureWithPubKey { signature, path } in signatures {
			// 	let pub_key = match RsaPub::from_pem_file(path) {
			// 		Ok(p) => p,
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	};
			// 	match pub_key.verify_sha256(&signature[..], &data[..]) {
			// 		Ok(_) => {}
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	}
			// }

			ok_or_return!(std::fs::write(&state.pivot_file, executable));
			ok_or_return!(set_permissions(
				&state.pivot_file,
				Permissions::from_mode(0o111)
			));

			Some(ProtocolMsg::SuccessResponse)
		} else {
			None
		}
	}
}
