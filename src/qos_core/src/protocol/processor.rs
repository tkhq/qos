//! Quorum protocol processor
use borsh::BorshDeserialize;
use nix::sys::time::{TimeVal, TimeValLike};
use qos_nsm::NsmProvider;

use super::{
	error::ProtocolError, msg::ProtocolMsg, state::ProtocolState,
	ProtocolPhase, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use crate::io::MAX_PAYLOAD_SIZE;
use crate::{client::Client, handles::Handles, io::SocketAddress, server};

/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct Processor {
	app_client: Client,
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
		let app_client = Client::new(
			app_addr,
			TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
		);

		Self {
			app_client,
			state: ProtocolState::new(
				attestor,
				handles,
				test_only_init_phase_override,
			),
		}
	}
}

impl server::RequestProcessor for Processor {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_PAYLOAD_SIZE {
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
					.app_client
					.send(&data)
					.map(|data| ProtocolMsg::ProxyResponse { data })
					.map_err(|e| ProtocolMsg::ProtocolErrorResponse(e.into()));

				match result {
					Ok(msg_resp) | Err(msg_resp) => borsh::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed."),
				}
			}
			_ => self.state.handle_msg(&msg_req),
		}
	}
}
