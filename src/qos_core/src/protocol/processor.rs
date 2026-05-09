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
			.to_json_wire()
			.expect("ProtocolMsg can always serialize to JSON. qed.");
		}

		let Ok((msg_req, encoding)) = ProtocolMsg::from_wire(req_bytes) else {
			return ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::ProtocolMsgDeserialization,
			)
			.to_json_wire()
			.expect("ProtocolMsg can always serialize to JSON. qed.");
		};

		let mut state = self.state.write().await;
		let response =
			tokio::task::block_in_place(|| state.handle_msg_response(&msg_req));
		response.to_wire(encoding).unwrap_or_else(|_| {
			ProtocolMsg::ProtocolErrorResponse(ProtocolError::InvalidMsg)
				.to_json_wire()
				.expect("ProtocolMsg can always serialize to JSON. qed.")
		})
	}
}

#[cfg(test)]
mod tests {
	use borsh::BorshDeserialize;
	use qos_nsm::mock::MockNsm;

	use super::*;
	use crate::{
		handles::Handles,
		protocol::{ProtocolPhase, ProtocolState},
		server::RequestProcessor,
	};

	fn test_state() -> SharedProtocolState {
		let root = std::env::temp_dir().join(format!(
			"qos-protocol-processor-test-{}",
			std::process::id()
		));
		std::fs::create_dir_all(&root).unwrap();
		ProtocolState::new(
			Box::new(MockNsm),
			Handles::new(
				root.join("ephemeral").to_string_lossy().into_owned(),
				root.join("quorum").to_string_lossy().into_owned(),
				root.join("manifest").to_string_lossy().into_owned(),
				root.join("pivot").to_string_lossy().into_owned(),
			),
			None,
		)
		.shared()
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn json_request_gets_json_response() {
		let processor = ProtocolProcessor::new(test_state());
		let req = ProtocolMsg::StatusRequest.to_json_wire().unwrap();
		let resp = processor.process(&req).await;

		let (msg, encoding) = ProtocolMsg::from_wire(&resp).unwrap();
		assert_eq!(encoding, super::super::msg::ProtocolMsgEncoding::Json);
		assert_eq!(
			msg,
			ProtocolMsg::StatusResponse(
				ProtocolPhase::WaitingForBootInstruction
			)
		);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn borsh_request_gets_borsh_response() {
		let processor = ProtocolProcessor::new(test_state());
		let req = ProtocolMsg::StatusRequest.to_borsh_wire().unwrap();
		let resp = processor.process(&req).await;

		let msg = ProtocolMsg::try_from_slice(&resp).unwrap();
		assert_eq!(
			msg,
			ProtocolMsg::StatusResponse(
				ProtocolPhase::WaitingForBootInstruction
			)
		);
	}
}
