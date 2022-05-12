use aws_nitro_enclaves_nsm_api as nsm;

mod attestor;
mod msg;
mod provisioner;

use attestor::*;
pub use attestor::{MockNsm, Nsm};
pub use msg::*;
pub use provisioner::SECRET_FILE;
use provisioner::*;

use crate::server;

type ProtocolHandler<A> =
	dyn Fn(&ProtocolMsg, &mut ProtocolState<A>) -> Option<ProtocolMsg>;

pub struct ProtocolState<A: NsmProvider> {
	provisioner: SecretProvisioner,
	// TODO: make this gneric over NsmProvider
	attestor: A,
}

impl<A: NsmProvider> ProtocolState<A> {
	pub fn new(attestor: A) -> Self {
		let provisioner = SecretProvisioner::new();
		Self { attestor, provisioner }
	}
}

pub struct Executor<A: NsmProvider> {
	routes: Vec<Box<ProtocolHandler<A>>>,
	state: ProtocolState<A>,
}

impl<A: 'static + NsmProvider> Executor<A> {
	pub fn new(attestor: A) -> Self {
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

impl<A: NsmProvider> server::Routable for Executor<A> {
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

	pub fn empty<A: NsmProvider>(
		req: &ProtocolMsg,
		_state: &mut ProtocolState<A>,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EmptyRequest = req {
			Some(ProtocolMsg::EmptyResponse)
		} else {
			None
		}
	}

	pub fn echo<A: NsmProvider>(
		req: &ProtocolMsg,
		_state: &mut ProtocolState<A>,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EchoRequest(e) = req {
			Some(ProtocolMsg::EchoResponse(e.clone()))
		} else {
			None
		}
	}

	pub fn provision<A: NsmProvider>(
		req: &ProtocolMsg,
		state: &mut ProtocolState<A>,
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

	pub fn reconstruct<A: NsmProvider>(
		req: &ProtocolMsg,
		state: &mut ProtocolState<A>,
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

	pub fn nsm<A: NsmProvider>(
		req: &ProtocolMsg,
		state: &mut ProtocolState<A>,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest(_nsmr) = req {
			let fd = state.attestor.nsm_init();
			let response = state
				.attestor
				.nsm_process_request(fd, nsm::api::Request::DescribeNSM);
			println!("NSM process request: {:?}", response);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}
}
