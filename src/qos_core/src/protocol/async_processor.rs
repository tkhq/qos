//! Quorum protocol processor
use std::sync::Arc;

use borsh::BorshDeserialize;
use tokio::sync::Mutex;

use super::{
	error::ProtocolError, msg::ProtocolMsg, state::ProtocolState, ProtocolPhase,
};
use crate::{
	async_server::AsyncRequestProcessor,
	io::{IOError, SharedAsyncStreamPool},
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Helper type to keep `ProtocolState` shared using `Arc<Mutex<ProtocolState>>`
type SharedProtocolState = Arc<Mutex<ProtocolState>>;

impl ProtocolState {
	/// Wrap this `ProtocolState` into a `Mutex` in an `Arc`.
	pub fn shared(self) -> SharedProtocolState {
		Arc::new(Mutex::new(self))
	}
}

/// Enclave state machine that executes when given a `ProtocolMsg`.
#[derive(Clone)]
pub struct AsyncProcessor {
	app_pool: SharedAsyncStreamPool,
	state: SharedProtocolState,
}

impl AsyncProcessor {
	/// Create a new `Self`.
	#[must_use]
	pub fn new(
		state: SharedProtocolState,
		app_pool: SharedAsyncStreamPool,
	) -> Self {
		Self { app_pool, state }
	}

	/// Helper to get phase between locking the shared state
	async fn get_phase(&self) -> ProtocolPhase {
		self.state.lock().await.get_phase()
	}

	/// Expands the app pool to given pool size
	pub async fn expand_to(&mut self, pool_size: u32) -> Result<(), IOError> {
		self.app_pool.write().await.expand_to(pool_size)
	}
}

impl AsyncRequestProcessor for AsyncProcessor {
	async fn process(&self, req_bytes: Vec<u8>) -> Vec<u8> {
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
		if let ProtocolMsg::ProxyRequest { data } = msg_req {
			let phase = self.get_phase().await;

			if phase != ProtocolPhase::QuorumKeyProvisioned {
				let err = ProtocolError::NoMatchingRoute(phase);
				return borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(err))
					.expect("ProtocolMsg can always be serialized. qed.");
			}

			let result = self
				.app_pool
				.read()
				.await
				.get()
				.await
				.call(&data)
				.await
				.map(|data| ProtocolMsg::ProxyResponse { data })
				.map_err(|_e| {
					ProtocolMsg::ProtocolErrorResponse(ProtocolError::IOError)
				});

			match result {
				Ok(msg_resp) | Err(msg_resp) => borsh::to_vec(&msg_resp)
					.expect("ProtocolMsg can always be serialized. qed."),
			}
		} else {
			// handle all the others here
			self.state.lock().await.handle_msg(&msg_req)
		}
	}
}
