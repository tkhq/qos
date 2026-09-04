//! Versioned manifest helpers.

use std::{borrow::Cow, io::Error};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::protocol::{Hash256, ProtocolError, QosHash};
#[cfg(test)]
use std::net::IpAddr;

use super::{
	Approval, BridgeConfig, Manifest, ManifestEnvelope, ManifestEnvelopeV0,
	ManifestSet, ManifestV0, Namespace, NitroConfig, RestartPolicy, ShareSet,
};

mod builder;
pub mod v2;
pub mod v3;

pub use builder::{ManifestBuilder, ManifestBuilderError};
pub use v2::{DnsConfig, ManifestEnvelopeV2, ManifestV2};
pub use v3::{
	EnclaveV3, ManifestEnvelopeV3, ManifestV3, OciDigest, OciImageRef,
	OciMount, OciName, OciPath, OciRestartPolicy, VolumeV3, WorkloadV3,
};

/// Schema version used by versioned manifest tooling.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	Copy,
	Default,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ManifestVersion {
	/// Backwards-compatible manifest schema.
	V1,
	/// Explicitly versioned JSON manifest schema.
	#[default]
	V2,
	/// OCI workload manifest schema.
	V3,
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

/// Whether `buf` is a JSON object carrying a top-level `version` key.
fn declares_a_version(buf: &[u8]) -> bool {
	serde_json::from_slice::<serde_json::Value>(buf)
		.ok()
		.and_then(|value| value.get("version").cloned())
		.is_some()
}

/// Whether `buf` is a JSON envelope whose `manifest` declares a `version`.
fn enveloped_manifest_declares_a_version(buf: &[u8]) -> bool {
	serde_json::from_slice::<serde_json::Value>(buf)
		.ok()
		.and_then(|value| value.get("manifest")?.get("version").cloned())
		.is_some()
}

/// A manifest decoded with schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum VersionedManifest {
	/// OCI workload manifest schema.
	V3(ManifestV3),
	/// Explicitly versioned JSON manifest schema.
	V2(ManifestV2),
	/// Backwards-compatible manifest schema.
	V1(Manifest),
	/// Legacy original manifest schema.
	V0(ManifestV0),
}

impl From<ManifestV3> for VersionedManifest {
	fn from(value: ManifestV3) -> Self {
		Self::V3(value)
	}
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
			Self::V3(_) => Err(borsh::io::Error::other(
				"manifest v3 is json-only and cannot be borsh serialized",
			)),
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
		super::decode_borsh(&buf, Self::V1, Self::V0)
	}
}

impl VersionedManifest {
	/// Return the manifest hash using the encoding for the embedded schema.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V3(manifest) => canonical_json_hash(manifest),
			Self::V2(manifest) => canonical_json_hash(manifest),
			Self::V1(manifest) => manifest.qos_hash(),
			Self::V0(manifest) => manifest.qos_hash(),
		}
	}

	/// Return the manifest namespace.
	#[must_use]
	pub fn namespace(&self) -> &Namespace {
		match self {
			Self::V3(manifest) => &manifest.namespace,
			Self::V2(manifest) => &manifest.namespace,
			Self::V1(manifest) => &manifest.namespace,
			Self::V0(manifest) => &manifest.namespace,
		}
	}

	/// Return the manifest set authorized to approve manifest changes.
	#[must_use]
	pub fn manifest_set(&self) -> &ManifestSet {
		match self {
			Self::V3(manifest) => &manifest.manifest_set,
			Self::V2(manifest) => &manifest.manifest_set,
			Self::V1(manifest) => &manifest.manifest_set,
			Self::V0(manifest) => &manifest.manifest_set,
		}
	}

	/// Return the share set authorized to approve share material.
	#[must_use]
	pub fn share_set(&self) -> &ShareSet {
		match self {
			Self::V3(manifest) => &manifest.share_set,
			Self::V2(manifest) => &manifest.share_set,
			Self::V1(manifest) => &manifest.share_set,
			Self::V0(manifest) => &manifest.share_set,
		}
	}

	/// Return the enclave configuration.
	#[must_use]
	pub fn enclave(&self) -> Cow<'_, NitroConfig> {
		match self {
			Self::V3(manifest) => Cow::Owned(manifest.enclave.nitro_config()),
			Self::V2(manifest) => Cow::Borrowed(&manifest.enclave),
			Self::V1(manifest) => Cow::Borrowed(&manifest.enclave),
			Self::V0(manifest) => Cow::Borrowed(&manifest.enclave),
		}
	}

	/// Return the expected pivot binary hash.
	#[must_use]
	pub fn pivot_hash(&self) -> Option<&Hash256> {
		match self {
			Self::V3(_) => None,
			Self::V2(manifest) => Some(&manifest.pivot.hash),
			Self::V1(manifest) => Some(&manifest.pivot.hash),
			Self::V0(manifest) => Some(&manifest.pivot.hash),
		}
	}

	/// Return the pivot restart policy.
	#[must_use]
	pub fn restart(&self) -> Option<RestartPolicy> {
		match self {
			Self::V3(_) => None,
			Self::V2(manifest) => Some(manifest.pivot.restart),
			Self::V1(manifest) => Some(manifest.pivot.restart),
			Self::V0(manifest) => Some(manifest.pivot.restart),
		}
	}

	/// Return the pivot command-line arguments.
	#[must_use]
	pub fn args(&self) -> Option<&[String]> {
		match self {
			Self::V3(_) => None,
			Self::V2(manifest) => Some(&manifest.pivot.args),
			Self::V1(manifest) => Some(&manifest.pivot.args),
			Self::V0(manifest) => Some(&manifest.pivot.args),
		}
	}

	/// Return bridge configuration entries, or an empty slice for v0 manifests.
	#[must_use]
	pub fn bridge_config(&self) -> &[BridgeConfig] {
		match self {
			Self::V2(manifest) => &manifest.pivot.bridge_config,
			Self::V1(manifest) => &manifest.pivot.bridge_config,
			Self::V3(_) | Self::V0(_) => &[],
		}
	}

	/// Return whether pivot debug mode is enabled.
	#[must_use]
	pub fn debug_mode(&self) -> bool {
		match self {
			Self::V2(manifest) => manifest.pivot.debug_mode,
			Self::V1(manifest) => manifest.pivot.debug_mode,
			Self::V3(_) | Self::V0(_) => false,
		}
	}

	/// Return DNS resolver configuration for v2 manifests.
	#[must_use]
	pub fn dns_config(&self) -> Option<&DnsConfig> {
		match self {
			Self::V3(manifest) => manifest.dns.as_ref(),
			Self::V2(manifest) => manifest.dns.as_ref(),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return the human readable schema version label for this manifest.
	#[must_use]
	pub const fn version_label(&self) -> &'static str {
		match self {
			Self::V3(_) => "v3",
			Self::V2(_) => "v2",
			Self::V1(_) => "v1",
			Self::V0(_) => "v0",
		}
	}

	/// Read a manifest while preserving the recognized schema version.
	///
	/// The older schemas are recognized by shape, so a manifest that declares
	/// a `version` must decode as [`ManifestV2`] rather than fall back to one
	/// of them.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest schema or encoding, or when a manifest declares a
	/// `version` that does not match the schema it is written in.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if declares_a_version(buf) {
			let version =
				serde_json::from_slice::<serde_json::Value>(buf).ok().and_then(
					|value| value.get("version")?.as_str().map(str::to_owned),
				);
			return match version.as_deref() {
				Some("v3") => serde_json::from_slice::<ManifestV3>(buf)
					.and_then(|manifest| {
						manifest
							.validate()
							.map_err(serde::de::Error::custom)?;
						Ok(manifest)
					})
					.map(Self::V3),
				_ => serde_json::from_slice::<ManifestV2>(buf).map(Self::V2),
			}
			.map_err(|e| Error::other(e.to_string()));
		}
		if let Ok(manifest) = serde_json::from_slice::<Manifest>(buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<ManifestV0>(buf) {
			return Ok(Self::V0(manifest));
		}
		super::decode_borsh(buf, Self::V1, Self::V0)
	}

	/// Serialize this manifest using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V3(manifest) => qos_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
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
	/// Signed OCI workload manifest.
	V3(ManifestEnvelopeV3),
	/// Explicitly versioned JSON manifest envelope schema.
	V2(ManifestEnvelopeV2),
	/// Backwards-compatible manifest envelope schema.
	V1(ManifestEnvelope),
	/// Legacy original manifest envelope schema.
	V0(ManifestEnvelopeV0),
}

impl From<ManifestEnvelopeV3> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelopeV3) -> Self {
		Self::V3(value)
	}
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
			Self::V3(_) => Err(borsh::io::Error::other(
				"manifest envelope v3 is json-only and cannot be borsh serialized",
			)),
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
		super::decode_borsh(&buf, Self::V1, Self::V0)
	}
}

impl VersionedManifestEnvelope {
	/// Consume the envelope and return its embedded manifest.
	#[must_use]
	pub fn manifest(self) -> VersionedManifest {
		match self {
			Self::V3(envelope) => VersionedManifest::V3(envelope.manifest),
			Self::V2(envelope) => VersionedManifest::V2(envelope.manifest),
			Self::V1(envelope) => VersionedManifest::V1(envelope.manifest),
			Self::V0(envelope) => VersionedManifest::V0(envelope.manifest),
		}
	}

	/// Return approvals from manifest set members.
	#[must_use]
	pub fn manifest_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V3(envelope) => &envelope.manifest_set_approvals,
			Self::V2(envelope) => &envelope.manifest_set_approvals,
			Self::V1(envelope) => &envelope.manifest_set_approvals,
			Self::V0(envelope) => &envelope.manifest_set_approvals,
		}
	}

	/// Return approvals from share set members.
	#[must_use]
	pub fn share_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V3(envelope) => &envelope.share_set_approvals,
			Self::V2(envelope) => &envelope.share_set_approvals,
			Self::V1(envelope) => &envelope.share_set_approvals,
			Self::V0(envelope) => &envelope.share_set_approvals,
		}
	}

	/// Return the embedded manifest hash using its schema-specific encoding.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V3(envelope) => canonical_json_hash(&envelope.manifest),
			Self::V2(envelope) => canonical_json_hash(&envelope.manifest),
			Self::V1(envelope) => envelope.manifest.qos_hash(),
			Self::V0(envelope) => envelope.manifest.qos_hash(),
		}
	}

	/// Return the embedded manifest set.
	#[must_use]
	pub fn manifest_set(&self) -> &ManifestSet {
		match self {
			Self::V3(envelope) => &envelope.manifest.manifest_set,
			Self::V2(envelope) => &envelope.manifest.manifest_set,
			Self::V1(envelope) => &envelope.manifest.manifest_set,
			Self::V0(envelope) => &envelope.manifest.manifest_set,
		}
	}

	/// Return the expected pivot binary hash from the embedded manifest.
	#[must_use]
	pub fn pivot_hash(&self) -> Option<&Hash256> {
		match self {
			Self::V3(_) => None,
			Self::V2(envelope) => Some(&envelope.manifest.pivot.hash),
			Self::V1(envelope) => Some(&envelope.manifest.pivot.hash),
			Self::V0(envelope) => Some(&envelope.manifest.pivot.hash),
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
		super::ensure_unique_members(&self.manifest_set().members)?;

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
			// Ensure that the member only has 1 approval. We already checked
			// at the top of this function that each member has a unique
			// signing key, so hashing the full member record is sufficient.
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
	/// As with [`VersionedManifest::try_from_slice_compat`], an envelope whose
	/// manifest declares a `version` must decode as [`ManifestEnvelopeV2`].
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest envelope schema or encoding, or when the enveloped
	/// manifest declares a `version` that does not match its schema.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if enveloped_manifest_declares_a_version(buf) {
			let version = serde_json::from_slice::<serde_json::Value>(buf)
				.ok()
				.and_then(|value| {
					value
						.get("manifest")?
						.get("version")?
						.as_str()
						.map(str::to_owned)
				});
			return match version.as_deref() {
				Some("v3") => serde_json::from_slice::<ManifestEnvelopeV3>(buf)
					.and_then(|envelope| {
						envelope
							.manifest
							.validate()
							.map_err(serde::de::Error::custom)?;
						Ok(envelope)
					})
					.map(Self::V3),
				_ => serde_json::from_slice::<ManifestEnvelopeV2>(buf)
					.map(Self::V2),
			}
			.map_err(|e| Error::other(e.to_string()));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelope>(buf) {
			return Ok(Self::V1(envelope));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelopeV0>(buf)
		{
			return Ok(Self::V0(envelope));
		}
		super::decode_borsh(buf, Self::V1, Self::V0)
	}

	/// Serialize this manifest envelope using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V3(envelope) => qos_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
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
			dns: None,
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
	fn v2_manifest_omits_dns_when_absent() {
		let pair = P256Pair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let value = serde_json::to_value(&manifest).unwrap();

		assert!(value.get("dns").is_none());
	}

	#[test]
	fn v2_manifest_round_trips_dns_resolvers() {
		let pair = P256Pair::generate().unwrap();
		let mut manifest = sample_v2_manifest(sample_member(&pair));
		manifest.dns = Some(DnsConfig {
			resolvers: vec![
				"1.1.1.1".parse().unwrap(),
				"2606:4700:4700::1111".parse().unwrap(),
			],
		});

		let value = serde_json::to_value(&manifest).unwrap();
		assert_eq!(value["dns"]["resolvers"][0], "1.1.1.1");
		assert_eq!(value["dns"]["resolvers"][1], "2606:4700:4700::1111");

		let decoded: ManifestV2 = serde_json::from_value(value).unwrap();
		assert_eq!(decoded.dns, manifest.dns);
	}

	#[test]
	fn v2_manifest_rejects_invalid_dns_resolver() {
		let pair = P256Pair::generate().unwrap();
		let mut value =
			serde_json::to_value(sample_v2_manifest(sample_member(&pair)))
				.unwrap();
		value["dns"] = serde_json::json!({
			"resolvers": ["not-an-ip"]
		});

		assert!(serde_json::from_value::<ManifestV2>(value).is_err());
	}

	#[test]
	fn v2_manifest_rejects_a_version_other_than_v2() {
		let pair = P256Pair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let mut value = serde_json::to_value(&manifest).unwrap();

		for version in [
			serde_json::json!("v1"),
			serde_json::json!("v3"),
			serde_json::json!(2),
		] {
			value["version"] = version.clone();
			assert!(
				serde_json::from_value::<ManifestV2>(value.clone()).is_err(),
				"version {version} should not decode as a v2 manifest"
			);
		}

		value["version"] = serde_json::json!("v2");
		assert_eq!(
			serde_json::from_value::<ManifestV2>(value).unwrap(),
			manifest
		);
	}

	#[test]
	fn declared_version_never_falls_back_to_an_older_schema() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);

		let mut v1 =
			serde_json::to_value(sample_v1_manifest(member.clone())).unwrap();
		v1["version"] = serde_json::json!("v2");
		let error = VersionedManifest::try_from_slice_compat(
			&serde_json::to_vec(&v1).unwrap(),
		)
		.unwrap_err();
		assert!(error.to_string().contains("patchSet"), "{error}");

		let mut v0 =
			serde_json::to_value(sample_v0_manifest(member.clone())).unwrap();
		v0["version"] = serde_json::json!("v1");
		assert!(
			VersionedManifest::try_from_slice_compat(
				&serde_json::to_vec(&v0).unwrap()
			)
			.is_err()
		);

		// Undeclared manifests still resolve by shape.
		let v1 =
			serde_json::to_vec(&sample_v1_manifest(member.clone())).unwrap();
		assert!(matches!(
			VersionedManifest::try_from_slice_compat(&v1).unwrap(),
			VersionedManifest::V1(_)
		));
		let v0 = serde_json::to_vec(&sample_v0_manifest(member)).unwrap();
		assert!(matches!(
			VersionedManifest::try_from_slice_compat(&v0).unwrap(),
			VersionedManifest::V0(_)
		));
	}

	#[test]
	fn enveloped_declared_version_never_falls_back_to_an_older_schema() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);

		let envelope = ManifestEnvelope {
			manifest: sample_v1_manifest(member.clone()),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		let mut value = serde_json::to_value(&envelope).unwrap();
		value["manifest"]["version"] = serde_json::json!("v2");
		assert!(
			VersionedManifestEnvelope::try_from_slice_compat(
				&serde_json::to_vec(&value).unwrap()
			)
			.is_err()
		);

		let undeclared = serde_json::to_vec(&envelope).unwrap();
		assert!(matches!(
			VersionedManifestEnvelope::try_from_slice_compat(&undeclared)
				.unwrap(),
			VersionedManifestEnvelope::V1(_)
		));
	}

	#[test]
	fn versioned_manifest_dns_config_is_v2_only() {
		let pair = P256Pair::generate().unwrap();
		let member = sample_member(&pair);
		let mut v2 = sample_v2_manifest(member.clone());
		v2.dns =
			Some(DnsConfig { resolvers: vec!["1.1.1.1".parse().unwrap()] });

		assert_eq!(
			VersionedManifest::V2(v2).dns_config().unwrap().resolvers,
			vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
		);
		assert!(
			VersionedManifest::V1(sample_v1_manifest(member.clone()))
				.dns_config()
				.is_none()
		);
		assert!(
			VersionedManifest::V0(sample_v0_manifest(member))
				.dns_config()
				.is_none()
		);
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
	fn versioned_check_approvals_rejects_same_key_under_different_aliases() {
		let pair = P256Pair::generate().unwrap();
		let alias_a = QuorumMember {
			alias: "alias-a".to_string(),
			pub_key: pair.public_key().to_bytes(),
		};
		let alias_b = QuorumMember {
			alias: "alias-b".to_string(),
			pub_key: pair.public_key().to_bytes(),
		};

		let mut manifest = sample_v2_manifest(alias_a.clone());
		manifest.manifest_set = ManifestSet {
			threshold: 2,
			members: vec![alias_a.clone(), alias_b.clone()],
		};

		let manifest_hash = canonical_json_hash(&manifest);
		let signature = pair.sign(&manifest_hash).unwrap();
		let envelope = VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals: vec![
				Approval { signature: signature.clone(), member: alias_a },
				Approval { signature, member: alias_b },
			],
			share_set_approvals: vec![],
		});

		let err = envelope.check_approvals().unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateQuorumMember);
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

	#[test]
	fn ambiguous_borsh_manifest_is_rejected() {
		let mut manifest = ManifestV0::default();
		manifest.pivot.args = vec!["\u{1}".to_string(), "\0\0\0\0".to_string()];
		let envelope = ManifestEnvelopeV0 {
			manifest: manifest.clone(),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		let envelope_bytes = borsh::to_vec(&envelope).unwrap();
		let bytes = borsh::to_vec(&manifest).unwrap();

		assert!(ManifestEnvelope::try_from_slice(&envelope_bytes).is_ok());
		assert!(ManifestEnvelopeV0::try_from_slice(&envelope_bytes).is_ok());
		assert!(
			VersionedManifestEnvelope::try_from_slice_compat(&envelope_bytes)
				.is_err()
		);
		assert!(Manifest::try_from_slice(&bytes).is_ok());
		assert!(ManifestV0::try_from_slice(&bytes).is_ok());
		assert!(VersionedManifest::try_from_slice_compat(&bytes).is_err());
	}
}
