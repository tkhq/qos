//! Legacy borsh-encoded protocol types.
//!
//! This module contains the original borsh-serialized types for backward
//! compatibility during the migration to protobuf.

mod boot;
mod error;
mod genesis;
mod msg;

pub use boot::{
	Approval, Manifest, ManifestEnvelope, ManifestEnvelopeV0, ManifestSet,
	ManifestV0, MemberPubKey, Namespace, NitroConfig, PatchSet, PivotConfig,
	QuorumMember, RestartPolicy, ShareSet,
};
pub use error::ProtocolError;
pub use genesis::{
	GenesisMemberOutput, GenesisOutput, GenesisSet, RecoveredPermutation,
};
pub use msg::ProtocolMsg;
