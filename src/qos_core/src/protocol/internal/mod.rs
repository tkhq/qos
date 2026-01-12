//! Internal protocol types. The plan is to start using the proto defined types
// in all external APIs and then convert those to internal types to have minimal
// change to internal business logic.

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
