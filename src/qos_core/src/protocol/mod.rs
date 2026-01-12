//! Quorum protocol

use prost::Message;
use qos_crypto::sha_256;

mod error;
pub mod legacy;
pub mod msg;
pub mod proto;
pub mod services;
mod state;

pub use error::ProtocolError;
pub use state::ProtocolPhase;
pub(crate) use state::ProtocolState;

pub(crate) mod processor;
pub use processor::INITIAL_CLIENT_TIMEOUT;

/// 256bit hash
pub type Hash256 = [u8; 32];

/// Canonical hash of `QuorumOS` types using protobuf encoding.
pub trait QosHash {
	/// Get the canonical hash using proto encoding.
	fn qos_hash(&self) -> Hash256;
}

impl QosHash for legacy::Manifest {
	fn qos_hash(&self) -> Hash256 {
		let proto = qos_proto::Manifest::from(self);
		sha_256(&proto.encode_to_vec())
	}
}

impl QosHash for legacy::GenesisOutput {
	fn qos_hash(&self) -> Hash256 {
		let proto = qos_proto::GenesisOutput::from(self);
		sha_256(&proto.encode_to_vec())
	}
}

impl QosHash for legacy::QuorumMember {
	fn qos_hash(&self) -> Hash256 {
		let proto = qos_proto::QuorumMember::from(self);
		sha_256(&proto.encode_to_vec())
	}
}

impl QosHash for legacy::ManifestSet {
	fn qos_hash(&self) -> Hash256 {
		let proto = qos_proto::ManifestSet::from(self);
		sha_256(&proto.encode_to_vec())
	}
}
