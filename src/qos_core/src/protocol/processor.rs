//! Quorum protocol processor

use borsh::BorshDeserialize;

use super::{
	error::ProtocolError, msg::ProtocolMsg, SharedProtocolState,
	MAX_ENCODED_MSG_LEN,
};
use crate::server::RequestProcessor;

/// Enclave state machine that executes when given a `ProtocolMsg`.
#[derive(Clone)]
pub struct ProtocolProcessor {
	state: SharedProtocolState,
}

impl ProtocolProcessor {
	/// Create a new `Self` inside `Arc` and `Mutex`.
	#[must_use]
	pub fn new(state: SharedProtocolState) -> Self {
		Self { state }
	}
}

impl RequestProcessor for ProtocolProcessor {
	async fn process(&self, req_bytes: &[u8]) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let Ok(msg_req) = ProtocolMsg::try_from_slice(req_bytes) else {
			return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::ProtocolMsgDeserialization,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		};

		let mut state = self.state.write().await;
		tokio::task::block_in_place(|| state.handle_msg(&msg_req))
	}
}
