//! Versioned manifest schemas and dispatch helpers.

use borsh::BorshDeserialize;

use crate::protocol::Hash256;

pub mod v0;
pub mod v1;
pub mod v2;

/// Supported manifest schema versions.
#[derive(
	PartialEq, Eq, Debug, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum ManifestVersion {
	/// Original legacy Borsh manifest.
	V0,
	/// Backwards-compatible Borsh manifest with bridge/debug fields.
	V1,
	/// Explicitly versioned JSON manifest.
	V2,
}

/// A manifest decoded with its schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum VersionedManifest {
	/// Original legacy Borsh manifest.
	V0(v0::Manifest),
	/// Backwards-compatible Borsh manifest.
	V1(v1::Manifest),
	/// Explicitly versioned JSON manifest.
	V2(v2::Manifest),
}

impl VersionedManifest {
	/// Hash the manifest according to its versioned signing rules.
	///
	/// # Panics
	///
	/// Panics only if a typed manifest cannot be serialized, which indicates a
	/// schema bug.
	#[must_use]
	pub fn qos_hash(&self) -> Hash256 {
		match self {
			Self::V0(manifest) => qos_crypto::sha_256(
				&borsh::to_vec(manifest)
					.expect("v0 manifest implements borsh serialize"),
			),
			Self::V1(manifest) => qos_crypto::sha_256(
				&borsh::to_vec(manifest)
					.expect("v1 manifest implements borsh serialize"),
			),
			Self::V2(manifest) => qos_crypto::sha_256(
				&qos_json::to_vec(manifest)
					.expect("v2 manifest implements QOS JSON serialize"),
			),
		}
	}

	/// Decode a manifest, preserving the version that was recognized.
	///
	/// # Errors
	///
	/// Returns a Borsh error if all known formats fail.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		if let Ok(manifest) = serde_json::from_slice::<v2::Manifest>(buf) {
			return Ok(Self::V2(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<v1::Manifest>(buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<v0::Manifest>(buf) {
			return Ok(Self::V0(manifest));
		}
		if let Ok(manifest) = v1::Manifest::try_from_slice(buf) {
			return Ok(Self::V1(manifest));
		}

		v0::Manifest::try_from_slice(buf).map(Self::V0)
	}
}

/// Compatibility alias for callers still importing `ManifestV0`.
pub type ManifestV0 = v0::Manifest;
/// Compatibility alias for callers still importing `PivotConfigV0`.
pub type PivotConfigV0 = v0::PivotConfig;
