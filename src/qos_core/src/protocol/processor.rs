//! Quorum protocol processor

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
			return ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			)
			.to_canonical_json_vec();
		}

		let Ok(msg_req) = ProtocolMsg::from_json_slice(req_bytes) else {
			return ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::ProtocolMsgDeserialization,
			)
			.to_canonical_json_vec();
		};

		let mut state = self.state.write().await;
		tokio::task::block_in_place(|| state.handle_msg(&msg_req))
	}
}
