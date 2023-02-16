//! Quorum protocol

use borsh::BorshSerialize;
use qos_crypto::sha_256;

mod error;
pub mod msg;
mod processor;
pub mod services;
mod state;

pub use error::ProtocolError;
pub use processor::Processor;
pub use state::ProtocolPhase;
use state::ProtocolState;

/// 256bit hash
pub type Hash256 = [u8; 32];

/// Canonical hash of `QuorumOS` types.
pub trait QosHash: BorshSerialize {
	/// Get the canonical hash.
	fn qos_hash(&self) -> Hash256 {
		sha_256(&self.try_to_vec().expect("Implements borsh serialize"))
	}
}

// Blanket implement QosHash for any type that implements BorshSerialize.
impl<T: BorshSerialize> QosHash for T {}
