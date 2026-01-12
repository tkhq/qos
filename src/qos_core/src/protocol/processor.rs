//! Quorum protocol processor
use std::{sync::Arc, time::Duration};

use tokio::sync::RwLock;

use super::{
	error::ProtocolError,
	msg::ProtocolMsg,
	proto::{decode_proto_msg, encode_proto_msg},
	state::ProtocolState,
	ProtocolPhase,
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
			return encode_proto_msg(&ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			));
		}

		let msg_req = match decode_proto_msg(req_bytes) {
			Ok(msg) => msg,
			Err(_) => {
				return encode_proto_msg(&ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::ProtocolMsgDeserialization,
				));
			}
		};

		// handle Proxy outside of the state
		if let ProtocolMsg::ProxyRequest { data } = msg_req {
			let phase = self.get_phase().await;

			if phase != ProtocolPhase::QuorumKeyProvisioned {
				let err = ProtocolError::NoMatchingRoute(phase);
				return encode_proto_msg(&ProtocolMsg::ProtocolErrorResponse(err));
			}

			let result = self
				.app_client
				.call(&data)
				.await
				.map(|data| ProtocolMsg::ProxyResponse { data })
				.map_err(|e| ProtocolMsg::ProtocolErrorResponse(e.into()));

			match result {
				Ok(ref msg_resp) | Err(ref msg_resp) => encode_proto_msg(msg_resp),
			}
		} else {
			// handle all the others here
			self.state.write().await.handle_msg(&msg_req)
		}
	}
}
