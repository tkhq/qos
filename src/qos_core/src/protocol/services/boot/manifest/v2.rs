//! Explicitly versioned JSON manifest schema (v2).

use super::shared;
use crate::protocol::Hash256;

/// v2 uses the v1 restart policy shape unchanged.
pub type RestartPolicy = super::v1::RestartPolicy;
/// v2 uses the v1 bridge configuration shape unchanged.
pub type BridgeConfig = super::v1::BridgeConfig;
/// v2 uses the v1 namespace shape unchanged.
pub type Namespace = super::v1::Namespace;
/// v2 uses the v1 manifest set shape unchanged.
pub type ManifestSet = super::v1::ManifestSet;
/// v2 uses the v1 share set shape unchanged.
pub type ShareSet = super::v1::ShareSet;
/// v2 uses the v1 nitro config shape unchanged.
pub type NitroConfig = super::v1::NitroConfig;
/// v2 uses the v1 patch set shape unchanged.
pub type PatchSet = super::v1::PatchSet;
/// v2 uses the v1 approval shape unchanged.
pub type Approval = super::v1::Approval;
/// v2 reuses the shared pivot environment map.
pub type PivotEnv = crate::protocol::services::boot::PivotEnv;

/// JSON-only pivot binary configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotConfigV2 {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Bridge host configuration for the pivot is a set of per-port rules.
	pub bridge_config: Vec<BridgeConfig>,
	/// Whether we're invoking the enclave and pivot in DEBUG mode.
	pub debug_mode: bool,
	/// Arguments to invoke the binary with.
	pub args: Vec<String>,
	/// Environment variables to inject into the pivot process.
	#[serde(default, skip_serializing_if = "PivotEnv::is_empty")]
	pub env: PivotEnv,
}

/// Explicitly versioned JSON manifest (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestV2 {
	/// Manifest schema version.
	pub version: super::ManifestVersion,
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfigV2,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold.
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold.
	pub patch_set: PatchSet,
}

/// Explicitly versioned JSON manifest envelope (v2).
pub type ManifestEnvelopeV2 = shared::ManifestEnvelope<ManifestV2>;
