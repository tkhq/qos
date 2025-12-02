//! Quorum protocol

use std::{sync::Arc, time::Duration};

use borsh::BorshSerialize;
use qos_crypto::sha_256;

mod error;
pub mod msg;
pub mod services;
mod state;

pub use error::ProtocolError;
pub use state::ProtocolPhase;
pub(crate) use state::ProtocolState;

pub(crate) mod processor;
use tokio::sync::RwLock;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Initial client timeout for the processor until the Manifest says otherwise, see reaper.rs
pub const INITIAL_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// 256bit hash
pub type Hash256 = [u8; 32];

/// Canonical hash of `QuorumOS` types.
pub trait QosHash: BorshSerialize {
	/// Get the canonical hash.
	fn qos_hash(&self) -> Hash256 {
		sha_256(&borsh::to_vec(self).expect("Implements borsh serialize"))
	}
}

// Blanket implement QosHash for any type that implements BorshSerialize.
impl<T: BorshSerialize> QosHash for T {}

/// Helper type to keep `ProtocolState` shared using `Arc<Mutex<ProtocolState>>`
type SharedProtocolState = Arc<RwLock<ProtocolState>>;

impl ProtocolState {
	/// Wrap this `ProtocolState` into a `Mutex` in an `Arc`.
	pub fn shared(self) -> SharedProtocolState {
		Arc::new(RwLock::new(self))
	}
}
