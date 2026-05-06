//! Versioned manifest schemas and dispatch helpers.

use crate::protocol::{Hash256, QosHash, QosHashJson};

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
	V0(v0::ManifestV0),
	/// Backwards-compatible Borsh manifest.
	V1(v1::ManifestV1),
	/// Explicitly versioned JSON manifest.
	V2(v2::ManifestV2),
}

impl VersionedManifest {
	/// Hash the manifest according to its versioned signing rules.
	///
	/// v0 and v1 hash Borsh bytes; v2 hashes canonical QOS JSON bytes.
	#[must_use]
	pub fn qos_hash(&self) -> Hash256 {
		match self {
			Self::V0(manifest) => manifest.qos_hash(),
			Self::V1(manifest) => manifest.qos_hash(),
			Self::V2(manifest) => manifest.qos_hash_json(),
		}
	}

	/// Decode a manifest, preserving the version that was recognized.
	///
	/// Read order: versioned JSON v2 → unversioned JSON v1 → unversioned JSON
	/// v0 → Borsh v1 → Borsh v0.
	///
	/// v2 JSON is unambiguous because the `version` field is required. v0
	/// JSON is a hypothetical (v0 is a Borsh legacy type) and may classify as
	/// v1 if it satisfies v1's serde defaults; this is acceptable because
	/// neither v0 nor v1 carries a discriminator and v0-on-disk JSON is not
	/// produced by any in-tree code path.
	///
	/// # Errors
	///
	/// Returns a Borsh error if all known formats fail.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		if let Ok(manifest) = serde_json::from_slice::<v2::ManifestV2>(buf) {
			return Ok(Self::V2(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<v1::ManifestV1>(buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<v0::ManifestV0>(buf) {
			return Ok(Self::V0(manifest));
		}
		if let Ok(manifest) = v1::ManifestV1::try_from_slice(buf) {
			return Ok(Self::V1(manifest));
		}

		v0::ManifestV0::try_from_slice(buf).map(Self::V0)
	}
}
