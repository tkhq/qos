//! Quorum protocol processor
use borsh::BorshDeserialize;
use qos_nsm::NsmProvider;

use super::{
	error::ProtocolError, msg::ProtocolMsg, state::ProtocolState, ProtocolPhase,
};
use crate::{
	async_server::AsyncRequestProcessor, handles::Handles, io::AsyncStreamPool,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct AsyncProcessor {
	app_pool: AsyncStreamPool,
	state: ProtocolState,
}

impl AsyncProcessor {
	/// Create a new `Self`.
	#[must_use]
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		app_pool: AsyncStreamPool,
		test_only_init_phase_override: Option<ProtocolPhase>,
	) -> Self {
		Self {
			app_pool,
			state: ProtocolState::new(
				attestor,
				handles,
				test_only_init_phase_override,
			),
		}
	}
}

impl AsyncRequestProcessor for AsyncProcessor {
	async fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
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

		// handle Proxy outside of the state
		match msg_req {
			ProtocolMsg::ProxyRequest { data } => {
				let phase = self.state.get_phase();
				if phase != ProtocolPhase::QuorumKeyProvisioned {
					let err = ProtocolError::NoMatchingRoute(phase);
					return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
						err,
					))
					.expect("ProtocolMsg can always be serialized. qed.");
				}

				let result = self
					.app_pool
					.get()
					.await
					.call(&data)
					.await
					.map(|data| ProtocolMsg::ProxyResponse { data })
					.map_err(|_e| {
						ProtocolMsg::ProtocolErrorResponse(
							ProtocolError::IOError,
						)
					});

				match result {
					Ok(msg_resp) | Err(msg_resp) => borsh::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed."),
				}
			}
			_ => self.state.handle_msg(&msg_req),
		}
	}
}
