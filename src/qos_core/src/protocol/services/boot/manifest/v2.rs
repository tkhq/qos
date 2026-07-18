//! Explicitly versioned JSON manifest schema (v2).

use crate::protocol::{
	Hash256,
	services::boot::{
		Approval, BridgeConfig, ManifestSet, Namespace, NitroConfig, PivotEnv,
		RestartPolicy, ShareSet,
	},
};

use super::ManifestVersion;

/// Pivot workload mode for v2 manifests.
#[derive(
	PartialEq, Eq, Debug, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum PivotKind {
	/// Legacy binary pivot workload.
	Binary,
	/// OCI image workload.
	OciImage,
}

/// OCI image digest approved by a v2 manifest.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize)]
pub struct OciDigest(String);

impl OciDigest {
	/// Create a new validated OCI sha256 digest.
	///
	/// # Errors
	///
	/// Returns [`String`] when the digest is not `sha256:<64 lowercase hex>`.
	pub fn new(value: impl Into<String>) -> Result<Self, String> {
		let value = value.into();
		let Some(hex) = value.strip_prefix("sha256:") else {
			return Err("OCI digest must start with sha256:".to_string());
		};
		if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
			return Err(
				"OCI digest must contain exactly 64 hex characters".to_string()
			);
		}
		if hex.bytes().any(|b| b.is_ascii_uppercase()) {
			return Err("OCI digest hex must be lowercase".to_string());
		}
		Ok(Self(value))
	}

	/// Return the digest string.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Return the lowercase hex portion of the digest.
	#[must_use]
	pub fn hex(&self) -> &str {
		self.0
			.strip_prefix("sha256:")
			.expect("validated digest always has sha256 prefix")
	}
}

impl<'de> serde::Deserialize<'de> for OciDigest {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		Self::new(value).map_err(serde::de::Error::custom)
	}
}

/// OCI platform requested by a v2 manifest.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciPlatform {
	/// Operating system. Must be `linux` in the first implementation.
	pub os: String,
	/// CPU architecture. Must be `amd64` in the first implementation.
	pub architecture: String,
}

impl OciPlatform {
	/// Return true when this platform is the supported first target.
	#[must_use]
	pub fn is_supported(&self) -> bool {
		self.os == "linux" && self.architecture == "amd64"
	}
}

/// Runtime limits for OCI image import and materialization.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciRuntimeLimits {
	/// Maximum compressed/imported bytes.
	#[serde(with = "qos_json::string_or_numeric")]
	pub max_compressed_bytes: u64,
	/// Maximum unpacked rootfs and tmpfs bytes.
	#[serde(with = "qos_json::string_or_numeric")]
	pub max_unpacked_bytes: u64,
	/// Maximum number of filesystem entries.
	#[serde(with = "qos_json::string_or_numeric")]
	pub max_entries: u64,
}

/// JSON-only pivot configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PivotConfigV2 {
	/// OCI image pivot workload.
	OciImage(PivotOciImageConfigV2),
	/// Legacy binary pivot workload.
	Binary(PivotBinaryConfigV2),
}

#[cfg(any(feature = "mock", test))]
impl Default for PivotConfigV2 {
	fn default() -> Self {
		Self::Binary(PivotBinaryConfigV2::default())
	}
}

impl PivotConfigV2 {
	/// Return the pivot workload kind.
	#[must_use]
	pub fn kind(&self) -> PivotKind {
		match self {
			Self::OciImage(_) => PivotKind::OciImage,
			Self::Binary(_) => PivotKind::Binary,
		}
	}

	/// Return the legacy binary pivot config, if present.
	#[must_use]
	pub fn binary(&self) -> Option<&PivotBinaryConfigV2> {
		match self {
			Self::Binary(config) => Some(config),
			Self::OciImage(_) => None,
		}
	}

	/// Return the OCI image pivot config, if present.
	#[must_use]
	pub fn oci_image(&self) -> Option<&PivotOciImageConfigV2> {
		match self {
			Self::OciImage(config) => Some(config),
			Self::Binary(_) => None,
		}
	}

	/// Return restart policy for either pivot kind.
	#[must_use]
	pub fn restart(&self) -> RestartPolicy {
		match self {
			Self::OciImage(config) => config.restart,
			Self::Binary(config) => config.restart,
		}
	}

	/// Return debug mode for either pivot kind.
	#[must_use]
	pub fn debug_mode(&self) -> bool {
		match self {
			Self::OciImage(config) => config.debug_mode,
			Self::Binary(config) => config.debug_mode,
		}
	}

	/// Return bridge configuration for either pivot kind.
	#[must_use]
	pub fn bridge_config(&self) -> &[BridgeConfig] {
		match self {
			Self::OciImage(config) => &config.bridge_config,
			Self::Binary(config) => &config.bridge_config,
		}
	}

	/// Return manifest-provided argv.
	#[must_use]
	pub fn args(&self) -> &[String] {
		match self {
			Self::OciImage(config) => config.args.as_deref().unwrap_or(&[]),
			Self::Binary(config) => &config.args,
		}
	}

	/// Return pivot env for either pivot kind.
	#[must_use]
	pub fn env(&self) -> &PivotEnv {
		match self {
			Self::OciImage(config) => &config.env,
			Self::Binary(config) => &config.env,
		}
	}
}

/// JSON-only binary pivot configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotBinaryConfigV2 {
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

/// JSON-only OCI image pivot configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotOciImageConfigV2 {
	/// Required discriminator.
	pub r#type: PivotKind,
	/// Digest of an OCI image manifest.
	pub digest: OciDigest,
	/// Required supported platform.
	pub platform: OciPlatform,
	/// Restart policy for running the OCI workload.
	pub restart: RestartPolicy,
	/// Optional argv override.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub args: Option<Vec<String>>,
	/// Environment variables to inject into the OCI workload process.
	#[serde(default, skip_serializing_if = "PivotEnv::is_empty")]
	pub env: PivotEnv,
	/// Whether QOS should pipe workload stdout/stderr to enclave logs.
	pub debug_mode: bool,
	/// VSOCK/TCP bridge rules exposed to the OCI workload.
	pub bridge_config: Vec<BridgeConfig>,
	/// Runtime limits for RAM-backed image handling.
	pub limits: OciRuntimeLimits,
	/// Optional complete OCI runtime configuration. QOS always replaces its
	/// root and process image-derived fields, while preserving namespaces,
	/// mounts, capabilities, cgroups, hooks, and other runtime fields.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub runtime: Option<oci_spec::runtime::Spec>,
}

/// Explicitly versioned JSON manifest (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestV2 {
	/// Manifest schema version.
	pub version: ManifestVersion,
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot workload configuration and verifiable values.
	pub pivot: PivotConfigV2,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold.
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
}

/// Explicitly versioned JSON manifest envelope (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEnvelopeV2 {
	/// Encapsulated manifest.
	pub manifest: ManifestV2,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<Approval>,
}
