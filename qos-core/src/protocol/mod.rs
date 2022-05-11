use aws_nitro_enclaves_nsm_api as nsm;

mod attestor;
mod provisioner;
pub mod types;

use crate::server;
use attestor::*;
use provisioner::*;

pub use attestor::MockNsm;
pub use provisioner::SECRET_FILE;
pub use types::*;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

pub struct ProtocolState {
	provisioner: SecretProvisioner,
	// TODO make this gneric over NsmProvider
	attestor: MockNsm,
}

impl ProtocolState {
	pub fn new(attestor: MockNsm) -> Self {
		let provisioner = SecretProvisioner::new();
		Self { attestor, provisioner }
	}
}

pub struct Router {
	routes: Vec<Box<ProtocolHandler>>,
}

impl Router {
	pub fn new() -> Self {
		Self {
			routes: vec![
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm),
			],
		}
	}
}

impl server::Routable<ProtocolState> for Router {
	fn process(
		&self,
		mut req_bytes: Vec<u8>,
		state: &mut ProtocolState,
	) -> Vec<u8> {
		use types::Serialize as _;

		let mut msg_req = match ProtocolMsg::deserialize(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => return ProtocolMsg::ErrorResponse.serialize(),
		};

		// outer scope
		for handler in self.routes.iter() {
			match handler(&msg_req, state) {
				Some(msg_resp) => return msg_resp.serialize(),
				None => continue,
			}
		}

		ProtocolMsg::ErrorResponse.serialize()
	}
}

pub mod handlers {
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
