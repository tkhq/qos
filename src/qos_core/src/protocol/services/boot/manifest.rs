//! Versioned manifest helpers.

use std::io::Error;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::protocol::{Hash256, ProtocolError, QosHash};

use super::{
	Approval, BridgeConfig, Manifest, ManifestEnvelope, ManifestEnvelopeV0,
	ManifestSet, ManifestV0, Namespace, NitroConfig, RestartPolicy, ShareSet,
};

pub mod v2;

pub use v2::{ManifestEnvelopeV2, ManifestV2};

/// Schema marker included only in v2 manifests.
#[derive(
	PartialEq, Eq, Debug, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum ManifestVersion {
	/// Explicitly versioned JSON manifest schema.
	V2,
}

/// Hash a serde value using canonical QOS JSON.
///
/// # Panics
///
/// Panics if `value` fails serialization, which would indicate a bug because
/// callers pass serde-serializable protocol types.
#[must_use]
pub fn canonical_json_hash<T: serde::Serialize>(value: &T) -> Hash256 {
	qos_json::hash(value).expect("Implements serde serialize")
}

/// A manifest decoded with schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VersionedManifest {
	/// Explicitly versioned JSON manifest schema.
	V2(ManifestV2),
	/// Backwards-compatible manifest schema.
	V1(Manifest),
	/// Legacy original manifest schema.
	V0(ManifestV0),
}

impl From<ManifestV2> for VersionedManifest {
	fn from(value: ManifestV2) -> Self {
		Self::V2(value)
	}
}

impl From<Manifest> for VersionedManifest {
	fn from(value: Manifest) -> Self {
		Self::V1(value)
	}
}

impl From<ManifestV0> for VersionedManifest {
	fn from(value: ManifestV0) -> Self {
		Self::V0(value)
	}
}

// NOTE: This is intentionally "illegal" for the v2 variant: v2 is JSON-only,
// but we still implement Borsh traits on the enum for v1/v0 backcompat.
impl BorshSerialize for VersionedManifest {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		match self {
			Self::V2(_) => Err(borsh::io::Error::other(
				"manifest v2 is json-only and cannot be borsh serialized",
			)),
			Self::V1(manifest) => manifest.serialize(writer),
			Self::V0(manifest) => manifest.serialize(writer),
		}
	}
}

impl BorshDeserialize for VersionedManifest {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let mut buf = vec![];
		reader.read_to_end(&mut buf)?;
		if let Ok(manifest) = Manifest::try_from_slice(&buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = ManifestV0::try_from_slice(&buf) {
			return Ok(Self::V0(manifest));
		}
		Err(borsh::io::Error::other("failed to decode borsh manifest as v1/v0"))
	}
}

impl VersionedManifest {
	/// Return the manifest hash using the encoding for the embedded schema.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V2(manifest) => canonical_json_hash(manifest),
			Self::V1(manifest) => manifest.qos_hash(),
			Self::V0(manifest) => manifest.qos_hash(),
		}
	}

	/// Return the manifest namespace.
	#[must_use]
	pub fn namespace(&self) -> &Namespace {
		match self {
			Self::V2(manifest) => &manifest.namespace,
			Self::V1(manifest) => &manifest.namespace,
			Self::V0(manifest) => &manifest.namespace,
		}
	}

	/// Return the manifest set authorized to approve manifest changes.
	#[must_use]
	pub fn manifest_set(&self) -> &ManifestSet {
		match self {
			Self::V2(manifest) => &manifest.manifest_set,
			Self::V1(manifest) => &manifest.manifest_set,
			Self::V0(manifest) => &manifest.manifest_set,
		}
	}

	/// Return the share set authorized to approve share material.
	#[must_use]
	pub fn share_set(&self) -> &ShareSet {
		match self {
			Self::V2(manifest) => &manifest.share_set,
			Self::V1(manifest) => &manifest.share_set,
			Self::V0(manifest) => &manifest.share_set,
		}
	}

	/// Return the enclave configuration.
	#[must_use]
	pub fn enclave(&self) -> &NitroConfig {
		match self {
			Self::V2(manifest) => &manifest.enclave,
			Self::V1(manifest) => &manifest.enclave,
			Self::V0(manifest) => &manifest.enclave,
		}
	}

	/// Return the expected pivot binary hash.
	#[must_use]
	pub fn pivot_hash(&self) -> &Hash256 {
		match self {
			Self::V2(manifest) => &manifest.pivot.hash,
			Self::V1(manifest) => &manifest.pivot.hash,
			Self::V0(manifest) => &manifest.pivot.hash,
		}
	}

	/// Return the pivot restart policy.
	#[must_use]
	pub fn restart(&self) -> RestartPolicy {
		match self {
			Self::V2(manifest) => manifest.pivot.restart,
			Self::V1(manifest) => manifest.pivot.restart,
			Self::V0(manifest) => manifest.pivot.restart,
		}
	}

	/// Return the pivot command-line arguments.
	#[must_use]
	pub fn args(&self) -> &[String] {
		match self {
			Self::V2(manifest) => &manifest.pivot.args,
			Self::V1(manifest) => &manifest.pivot.args,
			Self::V0(manifest) => &manifest.pivot.args,
		}
	}

	/// Return bridge configuration entries, or an empty slice for v0 manifests.
	#[must_use]
	pub fn bridge_config(&self) -> &[BridgeConfig] {
		match self {
			Self::V2(manifest) => &manifest.pivot.bridge_config,
			Self::V1(manifest) => &manifest.pivot.bridge_config,
			Self::V0(_) => &[],
		}
	}

	/// Return whether pivot debug mode is enabled.
	#[must_use]
	pub fn debug_mode(&self) -> bool {
		match self {
			Self::V2(manifest) => manifest.pivot.debug_mode,
			Self::V1(manifest) => manifest.pivot.debug_mode,
			Self::V0(_) => false,
		}
	}

	/// Read a manifest while preserving the recognized schema version.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest schema or encoding.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if let Ok(manifest) = serde_json::from_slice::<ManifestV2>(buf) {
			return Ok(Self::V2(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<Manifest>(buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<ManifestV0>(buf) {
			return Ok(Self::V0(manifest));
		}
		if let Ok(manifest) = Manifest::try_from_slice(buf) {
			return Ok(Self::V1(manifest));
		}

		ManifestV0::try_from_slice(buf)
			.map(Self::V0)
			.map_err(|e| Error::other(e.to_string()))
	}

	/// Serialize this manifest using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V2(manifest) => qos_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
			Self::V1(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
			Self::V0(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
		}
	}
}

/// A manifest envelope decoded with schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VersionedManifestEnvelope {
	/// Explicitly versioned JSON manifest envelope schema.
	V2(ManifestEnvelopeV2),
	/// Backwards-compatible manifest envelope schema.
	V1(ManifestEnvelope),
	/// Legacy original manifest envelope schema.
	V0(ManifestEnvelopeV0),
}

impl From<ManifestEnvelopeV2> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelopeV2) -> Self {
		Self::V2(value)
	}
}

impl From<ManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelope) -> Self {
		Self::V1(value)
	}
}

impl From<&ManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: &ManifestEnvelope) -> Self {
		Self::V1(value.clone())
	}
}

impl From<ManifestEnvelopeV0> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelopeV0) -> Self {
		Self::V0(value)
	}
}

impl From<&VersionedManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: &VersionedManifestEnvelope) -> Self {
		value.clone()
	}
}

impl From<&Box<VersionedManifestEnvelope>> for VersionedManifestEnvelope {
	fn from(value: &Box<VersionedManifestEnvelope>) -> Self {
		(**value).clone()
	}
}

// NOTE: Same backcompat carve-out as VersionedManifest above: the enum keeps
// a Borsh impl for v1/v0, while v2 explicitly errors.
impl BorshSerialize for VersionedManifestEnvelope {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		match self {
			Self::V2(_) => Err(borsh::io::Error::other(
				"manifest envelope v2 is json-only and cannot be borsh serialized",
			)),
			Self::V1(envelope) => envelope.serialize(writer),
			Self::V0(envelope) => envelope.serialize(writer),
		}
	}
}

impl BorshDeserialize for VersionedManifestEnvelope {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let mut buf = vec![];
		reader.read_to_end(&mut buf)?;
		if let Ok(envelope) = ManifestEnvelope::try_from_slice(&buf) {
			return Ok(Self::V1(envelope));
		}
		if let Ok(envelope) = ManifestEnvelopeV0::try_from_slice(&buf) {
			return Ok(Self::V0(envelope));
		}
		Err(borsh::io::Error::other(
			"failed to decode borsh manifest envelope as v1/v0",
		))
	}
}

impl VersionedManifestEnvelope {
	/// Consume the envelope and return its embedded manifest.
	#[must_use]
	pub fn manifest(self) -> VersionedManifest {
		match self {
			Self::V2(envelope) => VersionedManifest::V2(envelope.manifest),
			Self::V1(envelope) => VersionedManifest::V1(envelope.manifest),
			Self::V0(envelope) => VersionedManifest::V0(envelope.manifest),
		}
	}

	/// Return approvals from manifest set members.
	#[must_use]
	pub fn manifest_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.manifest_set_approvals,
			Self::V1(envelope) => &envelope.manifest_set_approvals,
			Self::V0(envelope) => &envelope.manifest_set_approvals,
		}
	}

	/// Return approvals from share set members.
	#[must_use]
	pub fn share_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.share_set_approvals,
			Self::V1(envelope) => &envelope.share_set_approvals,
			Self::V0(envelope) => &envelope.share_set_approvals,
		}
	}

	/// Return the embedded manifest hash using its schema-specific encoding.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V2(envelope) => canonical_json_hash(&envelope.manifest),
			Self::V1(envelope) => envelope.manifest.qos_hash(),
			Self::V0(envelope) => envelope.manifest.qos_hash(),
		}
	}

	/// Return the embedded manifest set.
	#[must_use]
	pub fn manifest_set(&self) -> &ManifestSet {
		match self {
			Self::V2(envelope) => &envelope.manifest.manifest_set,
			Self::V1(envelope) => &envelope.manifest.manifest_set,
			Self::V0(envelope) => &envelope.manifest.manifest_set,
		}
	}

	/// Return the expected pivot binary hash from the embedded manifest.
	#[must_use]
	pub fn pivot_hash(&self) -> &Hash256 {
		match self {
			Self::V2(envelope) => &envelope.manifest.pivot.hash,
			Self::V1(envelope) => &envelope.manifest.pivot.hash,
			Self::V0(envelope) => &envelope.manifest.pivot.hash,
		}
	}

	/// Verify manifest-set approvals against the embedded manifest hash and
	/// threshold policy.
	///
	/// # Errors
	///
	/// Returns a [`ProtocolError`] when signatures are invalid, members are
	/// unauthorized, duplicate approvals exist, or the threshold is not met.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		let manifest_hash = self.manifest_hash();
		let mut uniq_members = std::collections::HashSet::new();

		for approval in self.manifest_set_approvals() {
			let member_pub_key =
				qos_p256::P256Public::from_bytes(&approval.member.pub_key)?;
			let is_valid_signature = member_pub_key
				.verify(&manifest_hash, &approval.signature)
				.is_ok();
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}
			if !self.manifest_set().members.contains(&approval.member) {
				return Err(ProtocolError::NotManifestSetMember);
			}
			if !uniq_members.insert(approval.member.qos_hash()) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}

		if uniq_members.len() < self.manifest_set().threshold as usize {
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}

	/// Read a manifest envelope while preserving the recognized schema version.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest envelope schema or encoding.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelopeV2>(buf)
		{
			return Ok(Self::V2(envelope));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelope>(buf) {
			return Ok(Self::V1(envelope));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelopeV0>(buf)
		{
			return Ok(Self::V0(envelope));
		}
		if let Ok(envelope) = ManifestEnvelope::try_from_slice(buf) {
			return Ok(Self::V1(envelope));
		}

		ManifestEnvelopeV0::try_from_slice(buf)
			.map(Self::V0)
			.map_err(|e| Error::other(e.to_string()))
	}

	/// Serialize this manifest envelope using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V2(envelope) => qos_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
			Self::V1(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
			Self::V0(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use qos_p256::P256Pair;

	use super::*;
	use crate::protocol::{
		QosHash,
		services::boot::{
			MemberPubKey, PatchSet, PivotConfig, PivotConfigV0, PivotEnv,
			QuorumMember,
		},
	};

	fn sample_member(pair: &P256Pair) -> QuorumMember {
		QuorumMember {
			alias: "member-1".to_string(),
			pub_key: pair.public_key().to_bytes(),
		}
	}

	fn sample_v2_manifest(member: QuorumMember) -> ManifestV2 {
		ManifestV2 {
			version: ManifestVersion::V2,
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: v2::PivotConfigV2 {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				bridge_config: vec![],
				debug_mode: false,
				args: vec!["--foo".to_string()],
				env: PivotEnv::new(),
			},
			manifest_set: ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			},
			share_set: ShareSet { threshold: 1, members: vec![member] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
		}
	}

	fn sample_v1_manifest(member: QuorumMember) -> Manifest {
		Manifest {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: PivotConfig {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				bridge_config: vec![],
				debug_mode: false,
				args: vec!["--foo".to_string()],
			},
			manifest_set: ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			},
			share_set: ShareSet { threshold: 1, members: vec![member.clone()] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
			patch_set: PatchSet {
				threshold: 1,
				members: vec![MemberPubKey { pub_key: member.pub_key }],
			},
		}
	}

	fn sample_v0_manifest(member: QuorumMember) -> ManifestV0 {
		ManifestV0 {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: PivotConfigV0 {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				args: vec!["--foo".to_string()],
			},
			manifest_set: ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			},
			share_set: ShareSet { threshold: 1, members: vec![member.clone()] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
			patch_set: PatchSet {
				threshold: 1,
				members: vec![MemberPubKey { pub_key: member.pub_key }],
			},
		}
	}

	#[test]
	fn v2_manifest_decode_and_hash_uses_canonical_json() {
		let pair = P256Pair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let bytes = qos_json::to_vec(&manifest).unwrap();

		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();
		assert!(matches!(decoded, VersionedManifest::V2(_)));
		assert_eq!(decoded.manifest_hash(), canonical_json_hash(&manifest));
	}

	#[test]
	fn v2_envelope_decode_and_approval_verification_uses_json_hash() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);
		let manifest = sample_v2_manifest(member.clone());
		let manifest_hash = canonical_json_hash(&manifest);
		let envelope = ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals: vec![Approval {
				signature: pair.sign(&manifest_hash).unwrap(),
				member,
			}],
			share_set_approvals: vec![],
		};
		let bytes = qos_json::to_vec(&envelope).unwrap();

		let decoded =
			VersionedManifestEnvelope::try_from_slice_compat(&bytes).unwrap();
		assert!(matches!(decoded, VersionedManifestEnvelope::V2(_)));
		assert_eq!(decoded.manifest_hash(), manifest_hash);
		assert!(decoded.check_approvals().is_ok());
	}

	#[test]
	fn hash_dispatch_uses_borsh_for_v1_v0() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);
		let v1 = sample_v1_manifest(member.clone());
		let v0 = sample_v0_manifest(member);

		assert_eq!(
			VersionedManifest::V1(v1.clone()).manifest_hash(),
			v1.qos_hash()
		);
		assert_eq!(
			VersionedManifest::V0(v0.clone()).manifest_hash(),
			v0.qos_hash()
		);
	}

	#[test]
	fn borsh_serialization_rejects_v2_variants() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);
		let v2_manifest = sample_v2_manifest(member.clone());
		let v2_envelope = ManifestEnvelopeV2 {
			manifest: v2_manifest.clone(),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};

		assert!(borsh::to_vec(&VersionedManifest::V2(v2_manifest)).is_err());
		assert!(
			borsh::to_vec(&VersionedManifestEnvelope::V2(v2_envelope)).is_err()
		);
	}
}
