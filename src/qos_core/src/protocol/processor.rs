//! Quorum protocol processor
use std::sync::Arc;

use crate::io::{TimeVal, TimeValLike};
use borsh::BorshDeserialize;
use tokio::sync::RwLock;

use super::{
	error::ProtocolError, msg::ProtocolMsg, state::ProtocolState,
	ProtocolPhase, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use crate::{
	client::{ClientError, SocketClient},
	io::SharedStreamPool,
	server::RequestProcessor,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Helper type to keep `ProtocolState` shared using `Arc<Mutex<ProtocolState>>`
type SharedProtocolState = Arc<RwLock<ProtocolState>>;

impl ProtocolState {
	/// Wrap this `ProtocolState` into a `Mutex` in an `Arc`.
	pub fn shared(self) -> SharedProtocolState {
		Arc::new(RwLock::new(self))
	}
}

/// Enclave state machine that executes when given a `ProtocolMsg`.
#[derive(Clone)]
pub struct ProtocolProcessor {
	app_client: SocketClient,
	state: SharedProtocolState,
}

impl ProtocolProcessor {
	/// Create a new `Self` inside `Arc` and `Mutex`.
	#[must_use]
	pub fn new(
		state: SharedProtocolState,
		app_pool: SharedStreamPool,
	) -> Arc<RwLock<Self>> {
		let app_client = SocketClient::new(
			app_pool,
			TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
		);
		Arc::new(RwLock::new(Self { app_client, state }))
	}

	/// Helper to get phase between locking the shared state
	async fn get_phase(&self) -> ProtocolPhase {
		self.state.read().await.get_phase()
	}

	/// Expands the app pool to given pool size
	pub async fn expand_to(
		&mut self,
		pool_size: u8,
	) -> Result<(), ClientError> {
		self.app_client.expand_to(pool_size).await
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

		// handle Proxy outside of the state
		if let ProtocolMsg::ProxyRequest { data } = msg_req {
			let phase = self.get_phase().await;

			if phase != ProtocolPhase::QuorumKeyProvisioned {
				let err = ProtocolError::NoMatchingRoute(phase);
				return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(err))
					.expect("ProtocolMsg can always be serialized. qed.");
			}

			let result = self
				.app_client
				.call(&data)
				.await
				.map(|data| ProtocolMsg::ProxyResponse { data })
				.map_err(|e| ProtocolMsg::ProtocolErrorResponse(e.into()));

			match result {
				Ok(msg_resp) | Err(msg_resp) => borsh::to_vec(&msg_resp)
					.expect("ProtocolMsg can always be serialized. qed."),
			}
		} else {
			// handle all the others here
			self.state.write().await.handle_msg(&msg_req)
		}
	}
}
