//! Explicitly versioned JSON manifest schema.

use crate::protocol::{services::boot, Hash256};

/// JSON-only pivot binary configuration.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotConfig {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: boot::RestartPolicy,
	/// Bridge host configuration for the pivot is a set of per-port rules.
	pub bridge_config: Vec<boot::BridgeConfig>,
	/// Whether we're invoking the enclave and pivot in DEBUG mode.
	pub debug_mode: bool,
	/// Arguments to invoke the binary with.
	pub args: Vec<String>,
	/// Environment variables to inject into the pivot process.
	#[serde(default, skip_serializing_if = "boot::PivotEnv::is_empty")]
	pub env: boot::PivotEnv,
}

/// Explicitly versioned JSON manifest.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
	/// Manifest schema version.
	pub version: super::ManifestVersion,
	/// Namespace this manifest belongs too.
	pub namespace: boot::Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfig,
	/// Manifest Set members and threshold.
	pub manifest_set: boot::ManifestSet,
	/// Share Set members and threshold.
	pub share_set: boot::ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: boot::NitroConfig,
	/// Patch set members and threshold.
	pub patch_set: boot::PatchSet,
}

/// Explicitly versioned JSON manifest envelope.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEnvelope {
	/// Encapsulated manifest.
	pub manifest: Manifest,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<boot::Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<boot::Approval>,
}
