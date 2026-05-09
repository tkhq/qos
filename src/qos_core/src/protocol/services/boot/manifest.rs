//! Versioned manifest schemas and dispatch helpers.

use qos_p256::P256Public;

use crate::protocol::{
	services::boot::{
		Approval, BridgeConfig, ManifestSet, Namespace, NitroConfig, PatchSet,
		PivotEnv, RestartPolicy, ShareSet,
	},
	Hash256, ProtocolError, QosHash, QosHashJson,
};

mod shared;
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
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum VersionedManifest {
	/// Explicitly versioned JSON manifest.
	V2(v2::ManifestV2),
	/// Backwards-compatible Borsh manifest.
	V1(v1::ManifestV1),
	/// Original legacy Borsh manifest.
	V0(v0::ManifestV0),
}

impl From<v0::ManifestV0> for VersionedManifest {
	fn from(value: v0::ManifestV0) -> Self {
		Self::V0(value)
	}
}

impl From<&v0::ManifestV0> for VersionedManifest {
	fn from(value: &v0::ManifestV0) -> Self {
		Self::V0(value.clone())
	}
}

impl From<v1::ManifestV1> for VersionedManifest {
	fn from(value: v1::ManifestV1) -> Self {
		Self::V1(value)
	}
}

impl From<&v1::ManifestV1> for VersionedManifest {
	fn from(value: &v1::ManifestV1) -> Self {
		Self::V1(value.clone())
	}
}

impl From<v2::ManifestV2> for VersionedManifest {
	fn from(value: v2::ManifestV2) -> Self {
		Self::V2(value)
	}
}

impl From<&v2::ManifestV2> for VersionedManifest {
	fn from(value: &v2::ManifestV2) -> Self {
		Self::V2(value.clone())
	}
}

impl From<&VersionedManifest> for VersionedManifest {
	fn from(value: &VersionedManifest) -> Self {
		value.clone()
	}
}

impl VersionedManifest {
	/// Serialize using the manifest's storage-compatible JSON format.
	///
	/// v2 uses canonical QOS JSON. v0 and v1 use deployed legacy JSON with
	/// numeric fields encoded as JSON numbers.
	///
	/// # Errors
	///
	/// Returns an error if serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, borsh::io::Error> {
		match self {
			Self::V2(manifest) => qos_json::to_vec(manifest)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
			Self::V1(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
			Self::V0(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
		}
	}

	/// Hash the manifest according to its versioned signing rules.
	///
	/// v0 and v1 hash Borsh bytes; v2 hashes canonical QOS JSON bytes.
	#[must_use]
	pub fn qos_hash(&self) -> Hash256 {
		match self {
			Self::V2(manifest) => manifest.qos_hash_json(),
			Self::V1(manifest) => manifest.qos_hash(),
			Self::V0(manifest) => manifest.qos_hash(),
		}
	}

	/// Namespace this manifest belongs to.
	#[must_use]
	pub fn namespace(&self) -> &Namespace {
		match self {
			Self::V2(manifest) => &manifest.namespace,
			Self::V1(manifest) => &manifest.namespace,
			Self::V0(manifest) => &manifest.namespace,
		}
	}

	/// Manifest set members and threshold.
	#[must_use]
	pub fn manifest_set(&self) -> &ManifestSet {
		match self {
			Self::V2(manifest) => &manifest.manifest_set,
			Self::V1(manifest) => &manifest.manifest_set,
			Self::V0(manifest) => &manifest.manifest_set,
		}
	}

	/// Share set members and threshold.
	#[must_use]
	pub fn share_set(&self) -> &ShareSet {
		match self {
			Self::V2(manifest) => &manifest.share_set,
			Self::V1(manifest) => &manifest.share_set,
			Self::V0(manifest) => &manifest.share_set,
		}
	}

	/// Patch set members and threshold.
	#[must_use]
	pub fn patch_set(&self) -> &PatchSet {
		match self {
			Self::V2(manifest) => &manifest.patch_set,
			Self::V1(manifest) => &manifest.patch_set,
			Self::V0(manifest) => &manifest.patch_set,
		}
	}

	/// Nitro enclave configuration.
	#[must_use]
	pub fn enclave(&self) -> &NitroConfig {
		match self {
			Self::V2(manifest) => &manifest.enclave,
			Self::V1(manifest) => &manifest.enclave,
			Self::V0(manifest) => &manifest.enclave,
		}
	}

	/// Hash of the pivot binary expected by the manifest.
	#[must_use]
	pub fn pivot_hash(&self) -> &Hash256 {
		match self {
			Self::V2(manifest) => &manifest.pivot.hash,
			Self::V1(manifest) => &manifest.pivot.hash,
			Self::V0(manifest) => &manifest.pivot.hash,
		}
	}

	/// Restart policy for the pivot process.
	#[must_use]
	pub fn restart(&self) -> RestartPolicy {
		match self {
			Self::V2(manifest) => manifest.pivot.restart,
			Self::V1(manifest) => manifest.pivot.restart,
			Self::V0(manifest) => manifest.pivot.restart,
		}
	}

	/// Arguments to invoke the pivot binary with.
	#[must_use]
	pub fn args(&self) -> &[String] {
		match self {
			Self::V2(manifest) => &manifest.pivot.args,
			Self::V1(manifest) => &manifest.pivot.args,
			Self::V0(manifest) => &manifest.pivot.args,
		}
	}

	/// Pivot bridge host configuration.
	#[must_use]
	pub fn bridge_config(&self) -> &[BridgeConfig] {
		match self {
			Self::V2(manifest) => &manifest.pivot.bridge_config,
			Self::V1(manifest) => &manifest.pivot.bridge_config,
			Self::V0(_) => &[],
		}
	}

	/// Whether debug output should be printed for the pivot process.
	#[must_use]
	pub fn debug_mode(&self) -> bool {
		match self {
			Self::V2(manifest) => manifest.pivot.debug_mode,
			Self::V1(manifest) => manifest.pivot.debug_mode,
			Self::V0(_) => false,
		}
	}

	/// Environment variables to inject into the pivot process.
	#[must_use]
	pub fn env(&self) -> Option<&PivotEnv> {
		match self {
			Self::V2(manifest) => Some(&manifest.pivot.env),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Convert v0 to the v1-compatible schema when a caller needs Borsh-compatible
	/// non-v2 output.
	#[must_use]
	pub fn into_v1_compat(self) -> Option<v1::ManifestV1> {
		match self {
			Self::V2(_) => None,
			Self::V1(manifest) => Some(manifest),
			Self::V0(manifest) => Some(manifest.into()),
		}
	}

	/// Decode a manifest, preserving the version that was recognized.
	///
	/// Read order: versioned JSON v2 → unversioned JSON v1 → unversioned JSON
	/// v0 → Borsh v1 → Borsh v0.
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

/// A manifest envelope decoded with its schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VersionedManifestEnvelope {
	/// Explicitly versioned JSON manifest envelope.
	V2(v2::ManifestEnvelopeV2),
	/// Backwards-compatible Borsh manifest envelope.
	V1(v1::ManifestEnvelopeV1),
	/// Original legacy Borsh manifest envelope.
	V0(v0::ManifestEnvelopeV0),
}

impl From<v0::ManifestEnvelopeV0> for VersionedManifestEnvelope {
	fn from(value: v0::ManifestEnvelopeV0) -> Self {
		Self::V0(value)
	}
}

impl From<v1::ManifestEnvelopeV1> for VersionedManifestEnvelope {
	fn from(value: v1::ManifestEnvelopeV1) -> Self {
		Self::V1(value)
	}
}

impl From<&v1::ManifestEnvelopeV1> for VersionedManifestEnvelope {
	fn from(value: &v1::ManifestEnvelopeV1) -> Self {
		Self::V1(value.clone())
	}
}

impl From<v2::ManifestEnvelopeV2> for VersionedManifestEnvelope {
	fn from(value: v2::ManifestEnvelopeV2) -> Self {
		Self::V2(value)
	}
}

impl From<&VersionedManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: &VersionedManifestEnvelope) -> Self {
		value.clone()
	}
}

impl VersionedManifestEnvelope {
	/// Decode an envelope using the v2 extension and the pre-existing legacy
	/// fallback order: v2 JSON → v1 JSON → v1 Borsh → v0 Borsh.
	///
	/// A legacy v1 JSON envelope cannot be accidentally classified as v2: the
	/// v2 envelope contains a [`v2::ManifestV2`], and that nested manifest
	/// requires an explicit `version` field. Unversioned legacy JSON therefore
	/// fails the v2 parse before the v1 JSON fallback is attempted.
	///
	/// # Errors
	///
	/// Returns a Borsh error if all known formats fail.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		if let Ok(envelope) =
			serde_json::from_slice::<v2::ManifestEnvelopeV2>(buf)
		{
			return Ok(Self::V2(envelope));
		}
		if let Ok(envelope) =
			serde_json::from_slice::<v1::ManifestEnvelopeV1>(buf)
		{
			return Ok(Self::V1(envelope));
		}
		if let Ok(envelope) = v1::ManifestEnvelopeV1::try_from_slice(buf) {
			return Ok(Self::V1(envelope));
		}

		v0::ManifestEnvelopeV0::try_from_slice(buf).map(Self::V0)
	}

	/// Serialize using the envelope's native storage format.
	///
	/// v2 uses canonical QOS JSON. v0 and v1 use deployed legacy JSON with
	/// numeric fields encoded as JSON numbers.
	///
	/// # Errors
	///
	/// Returns an error if Borsh or QOS JSON serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, borsh::io::Error> {
		match self {
			Self::V2(envelope) => qos_json::to_vec(envelope)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
			Self::V1(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
			Self::V0(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| borsh::io::Error::other(e.to_string())),
		}
	}

	/// Hash the enclosed manifest according to its versioned signing rules.
	#[must_use]
	pub fn qos_hash(&self) -> Hash256 {
		self.manifest().qos_hash()
	}

	/// The enclosed manifest, preserving version.
	#[must_use]
	pub fn manifest(&self) -> VersionedManifest {
		match self {
			Self::V2(envelope) => {
				VersionedManifest::V2(envelope.manifest.clone())
			}
			Self::V1(envelope) => {
				VersionedManifest::V1(envelope.manifest.clone())
			}
			Self::V0(envelope) => {
				VersionedManifest::V0(envelope.manifest.clone())
			}
		}
	}

	/// Manifest set approvals.
	#[must_use]
	pub fn manifest_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.manifest_set_approvals,
			Self::V1(envelope) => &envelope.manifest_set_approvals,
			Self::V0(envelope) => &envelope.manifest_set_approvals,
		}
	}

	/// Share set approvals.
	#[must_use]
	pub fn share_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.share_set_approvals,
			Self::V1(envelope) => &envelope.share_set_approvals,
			Self::V0(envelope) => &envelope.share_set_approvals,
		}
	}

	/// Record a share set approval.
	pub fn push_share_set_approval(&mut self, approval: Approval) {
		match self {
			Self::V2(envelope) => envelope.share_set_approvals.push(approval),
			Self::V1(envelope) => envelope.share_set_approvals.push(approval),
			Self::V0(envelope) => envelope.share_set_approvals.push(approval),
		}
	}

	/// Check if the encapsulated manifest has K valid approvals from the manifest
	/// approval set.
	///
	/// # Errors
	///
	/// Returns an error if an approval signature is invalid, an approver is not
	/// in the manifest set, an approver appears more than once, or fewer than
	/// the threshold number of unique members approved.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		let manifest = self.manifest();
		let manifest_hash = manifest.qos_hash();
		let mut uniq_members = std::collections::HashSet::new();

		for approval in self.manifest_set_approvals() {
			let member_pub_key =
				P256Public::from_bytes(&approval.member.pub_key)?;
			if member_pub_key
				.verify(&manifest_hash, &approval.signature)
				.is_err()
			{
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}

			if !manifest.manifest_set().members.contains(&approval.member) {
				return Err(ProtocolError::NotManifestSetMember);
			}

			if !uniq_members.insert(approval.member.qos_hash()) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}

		if uniq_members.len() < manifest.manifest_set().threshold as usize {
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}

	/// Convert v0 to the v1-compatible schema when a caller needs Borsh-compatible
	/// non-v2 output.
	#[must_use]
	pub fn into_v1_compat(self) -> Option<v1::ManifestEnvelopeV1> {
		match self {
			Self::V2(_) => None,
			Self::V1(envelope) => Some(envelope),
			Self::V0(envelope) => Some(v1::ManifestEnvelopeV1 {
				manifest: envelope.manifest.into(),
				manifest_set_approvals: envelope.manifest_set_approvals,
				share_set_approvals: envelope.share_set_approvals,
			}),
		}
	}
}
