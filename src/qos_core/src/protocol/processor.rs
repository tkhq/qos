//! Quorum protocol processor
use borsh::BorshDeserialize;
use qos_nsm::NsmProvider;

use super::{
	error::ProtocolError, msg::ProtocolMsg, state::ProtocolState, ProtocolPhase,
};
use crate::{handles::Handles, io::SocketAddress, server};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct Processor {
	state: ProtocolState,
}

impl Processor {
	/// Create a new `Self`.
	#[must_use]
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		app_addr: SocketAddress,
		test_only_init_phase_override: Option<ProtocolPhase>,
	) -> Self {
		Self {
			state: ProtocolState::new(
				attestor,
				handles,
				app_addr,
				test_only_init_phase_override,
			),
		}
	}
}

impl server::RequestProcessor for Processor {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let Ok(msg_req) = ProtocolMsg::try_from_slice(&req_bytes) else {
			return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::ProtocolMsgDeserialization,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		};

		self.state.handle_msg(&msg_req)
	}
}
