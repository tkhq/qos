//! Original legacy manifest schema (v0).

use crate::protocol::{
	services::boot::{
		Approval, ManifestSet, Namespace, NitroConfig, PatchSet, RestartPolicy,
		ShareSet,
	},
	Hash256,
};

/// Pivot binary configuration, original version (v0).
#[derive(
	PartialEq,
	Eq,
	Clone,
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotConfigV0 {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Arguments to invoke the binary with. Leave this empty if none are
	/// needed.
	pub args: Vec<String>,
}

/// The original legacy manifest (v0).
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
pub struct ManifestV0 {
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfigV0,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold
	pub patch_set: PatchSet,
}

/// [`ManifestV0`] with accompanying [`Approval`]s.
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
pub struct ManifestEnvelopeV0 {
	/// Encapsulated manifest.
	pub manifest: ManifestV0,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<Approval>,
}
