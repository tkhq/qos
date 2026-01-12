//! Quorum protocol processor
use std::{sync::Arc, time::Duration};

use prost::Message;
use tokio::sync::RwLock;

use super::{
	msg::{protocol_msg, ProtocolMsg, ProtocolMsgExt},
	state::ProtocolState,
	ProtocolError, ProtocolPhase,
};
use crate::{
	client::{ClientError, SocketClient},
	io::SharedStreamPool,
	server::RequestProcessor,
};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Initial client timeout for the processor until the Manifest says otherwise, see reaper.rs
pub const INITIAL_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

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
		let app_client = SocketClient::new(app_pool, INITIAL_CLIENT_TIMEOUT);
		Arc::new(RwLock::new(Self { app_client, state }))
	}

	/// Helper to get phase between locking the shared state
	async fn get_phase(&self) -> ProtocolPhase {
		self.state.read().await.get_phase()
	}

	/// Sets the client timeout value for the `app_client`, maximum allowed value is `u16::MAX` milliseconds
	pub fn set_client_timeout(&mut self, timeout: Duration) {
		assert!(timeout.as_millis() < u16::MAX.into(), "client timeout > 65s");
		self.app_client.set_timeout(timeout);
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
			return ProtocolMsg::error_response(ProtocolError::OversizedPayload.into())
				.encode_to_vec();
		}

		let Ok(msg_req) = ProtocolMsg::decode(req_bytes) else {
			return ProtocolMsg::error_response(
				ProtocolError::ProtocolMsgDeserialization.into(),
			)
			.encode_to_vec();
		};

		// handle Proxy outside of the state
		if let Some(protocol_msg::Msg::ProxyRequest(ref proxy_req)) = msg_req.msg {
			let phase = self.get_phase().await;

			if phase != ProtocolPhase::QuorumKeyProvisioned {
				let err = ProtocolError::NoMatchingRoute(phase);
				return ProtocolMsg::error_response(err.into()).encode_to_vec();
			}

			let result = self
				.app_client
				.call(&proxy_req.data)
				.await
				.map(|data| ProtocolMsg::proxy_response(data))
				.map_err(|e| ProtocolMsg::error_response(ProtocolError::from(e).into()));

			match result {
				Ok(msg_resp) | Err(msg_resp) => msg_resp.encode_to_vec(),
			}
		} else {
			// handle all the others here
			self.state.write().await.handle_msg(&msg_req)
		}
	}
}
