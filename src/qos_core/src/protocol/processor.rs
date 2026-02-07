//! Quorum protocol processor

use std::sync::Arc;

use tokio::sync::RwLock;

use super::{
	error::ProtocolError, msg::ProtocolMsg, SharedProtocolState,
	MAX_ENCODED_MSG_LEN,
};
use crate::server::{RequestProcessor, SharedProcessor};

/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct ProtocolProcessor {
	state: SharedProtocolState,
}

impl ProtocolProcessor {
	/// Create a new `Self` inside `Arc` and `Mutex`.
	#[must_use]
	pub fn new(state: SharedProtocolState) -> SharedProcessor<Self> {
		Arc::new(RwLock::new(Self { state }))
	}
}

impl RequestProcessor for ProtocolProcessor {
	async fn process(&self, req_bytes: &[u8]) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return serde_json::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let Ok(msg_req) = serde_json::from_slice::<ProtocolMsg>(req_bytes)
		else {
			return serde_json::to_vec(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::ProtocolMsgDeserialization,
			))
			.expect("ProtocolMsg can always be serialized. qed.");
		};

		self.state.write().await.handle_msg(&msg_req)
	}
}
