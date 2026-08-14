//! Explicitly versioned JSON manifest schema (v2).

use std::net::IpAddr;

use crate::protocol::{
	Hash256,
	services::boot::{
		Approval, BridgeConfig, ManifestSet, Namespace, NitroConfig, PivotEnv,
		RestartPolicy, ShareSet,
	},
};

use super::ManifestVersion;

/// DNS resolver configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsConfig {
	/// Resolver IP addresses to write as `nameserver` entries.
	pub resolvers: Vec<IpAddr>,
}

/// JSON-only pivot binary configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestV2 {
	/// Manifest schema version. Always [`ManifestVersion::V2`]; any other
	/// value fails to deserialize.
	#[serde(deserialize_with = "deserialize_v2_version")]
	pub version: ManifestVersion,
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
	/// DNS resolver configuration for the enclave.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dns: Option<DnsConfig>,
}

/// Accept only `"v2"`. [`ManifestVersion`] doubles as the schema selector for
/// [`super::ManifestBuilder`], so it carries variants a [`ManifestV2`] can
/// never legitimately hold.
fn deserialize_v2_version<'de, D>(
	deserializer: D,
) -> Result<ManifestVersion, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::{Deserialize, de::Error};

	match ManifestVersion::deserialize(deserializer)? {
		ManifestVersion::V2 => Ok(ManifestVersion::V2),
		other => Err(D::Error::custom(format!(
			"manifest v2 requires version \"v2\", got {other:?}"
		))),
	}
}

/// Explicitly versioned JSON manifest envelope (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEnvelopeV2 {
	/// Encapsulated manifest.
	pub manifest: ManifestV2,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<Approval>,
}
