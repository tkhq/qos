//! Shared manifest building blocks reused across schema versions.

use crate::protocol::services::boot::Approval;

/// Shared manifest envelope structure used by all versions.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ManifestEnvelope<Manifest> {
	/// Encapsulated manifest.
	pub manifest: Manifest,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<Approval>,
}
