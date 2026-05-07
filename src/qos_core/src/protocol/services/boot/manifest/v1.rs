//! Backwards-compatible Borsh manifest schema (v1).

use std::{collections::HashSet, fmt};

use qos_p256::P256Public;

use super::shared;
use super::v0::{ManifestEnvelopeV0, ManifestV0, PivotConfigV0};
use crate::protocol::{
	services::boot::{
		BridgeConfig, ManifestSet, Namespace, NitroConfig, PatchSet,
		RestartPolicy, ShareSet,
	},
	Hash256, ProtocolError, QosHash,
};

/// Pivot binary configuration (v1).
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotConfigV1 {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Bridge host configuration for the pivot is a set of per-port rules.
	/// If set the pivot will service TCP with the provided ports and a bridge
	/// will provide the TCP -> VSOCK -> TCP streams. If not set the pivot will
	/// service VSOCK and the host side needs to be provided manually.
	pub bridge_config: Vec<BridgeConfig>,
	/// Whether we're invoking the enclave and pivot in DEBUG mode. This
	/// controls output piping.
	/// *NOTE*: this requires `DEBUG` and `LOGS` env var to be set to `true`
	/// when `qos_enclave` is running.
	pub debug_mode: bool,
	/// Arguments to invoke the binary with. Leave this empty if none are
	/// needed.
	pub args: Vec<String>,
}

impl From<PivotConfigV0> for PivotConfigV1 {
	fn from(value: PivotConfigV0) -> Self {
		Self {
			hash: value.hash,
			restart: value.restart,
			args: value.args,
			debug_mode: false,
			bridge_config: Vec::new(),
		}
	}
}

impl fmt::Debug for PivotConfigV1 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("PivotConfigV1")
			.field("hash", &qos_hex::encode(&self.hash))
			.field("restart", &self.restart)
			.field("bridge_config", &self.bridge_config)
			.field("debug_mode", &self.debug_mode)
			.field("args", &self.args.join(" "))
			.finish()
	}
}

/// The Manifest for the enclave (v1).
///
/// NOTE: we currently use JSON format for storing this value.
/// Since we don't have any `HashMap` inside the `ManifestV1` it works out of
/// the box. If we ever do need a map inside, we should use a `BTreeMap` to
/// ensure keys are sorted.
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
pub struct ManifestV1 {
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfigV1,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold
	pub patch_set: PatchSet,
}

impl From<ManifestV0> for ManifestV1 {
	fn from(old: ManifestV0) -> Self {
		Self {
			namespace: old.namespace,
			pivot: old.pivot.into(),
			manifest_set: old.manifest_set,
			share_set: old.share_set,
			enclave: old.enclave,
			patch_set: old.patch_set,
		}
	}
}

impl ManifestV1 {
	/// Read a `ManifestV1` in a backwards compatible way.
	///
	/// Callers should only use this after trying to parse the current JSON
	/// schema first. This helper attempts `ManifestV0` JSON before the
	/// current type, so direct use on current JSON can silently drop newer
	/// `pivot` fields that `ManifestV0` ignores. In-tree callers avoid that
	/// by going through `read_manifest`, which tries the current `ManifestV1`
	/// JSON parse before falling back here.
	///
	/// # Errors
	///
	/// Returns [`borsh::io::Error`] if deserialization fails for both the
	/// current and legacy formats.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		// try old version with json format
		if let Ok(v0) = serde_json::from_slice::<ManifestV0>(buf) {
			return Ok(v0.into());
		}

		let result = Self::try_from_slice(buf);

		// try loading the old version with borsh format
		if result.is_err() {
			let old = ManifestV0::try_from_slice(buf)?;

			Ok(old.into())
		} else {
			result
		}
	}
}

/// [`ManifestV1`] with accompanying [`Approval`]s.
pub type ManifestEnvelopeV1 = shared::ManifestEnvelope<ManifestV1>;

impl ManifestEnvelopeV1 {
	/// Check if the encapsulated manifest has K valid approvals from the
	/// manifest approval set.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::InvalidManifestApproval`] if a signature is
	/// invalid, [`ProtocolError::NotManifestSetMember`] if an approver is
	/// not in the manifest set, [`ProtocolError::DuplicateApproval`] if a
	/// member has more than one approval, or
	/// [`ProtocolError::NotEnoughApprovals`] if fewer than the threshold
	/// number of members approved.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		let mut uniq_members = HashSet::new();
		for approval in &self.manifest_set_approvals {
			let member_pub_key =
				P256Public::from_bytes(&approval.member.pub_key)?;

			let is_valid_signature = member_pub_key
				.verify(&self.manifest.qos_hash(), &approval.signature)
				.is_ok();
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}

			if !self.manifest.manifest_set.members.contains(&approval.member) {
				return Err(ProtocolError::NotManifestSetMember);
			}

			if !uniq_members.insert(approval.member.qos_hash()) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}

		if uniq_members.len() < self.manifest.manifest_set.threshold as usize {
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}

	/// Read a `ManifestEnvelopeV1` from a `u8` buffer, in a backwards
	/// compatible way.
	///
	/// # Errors
	///
	/// Returns [`borsh::io::Error`] if deserialization fails for both the
	/// current and legacy formats.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		let result = Self::try_from_slice(buf);

		if result.is_err() {
			let old = ManifestEnvelopeV0::try_from_slice(buf)?;

			Ok(Self {
				manifest: ManifestV1::from(old.manifest),
				manifest_set_approvals: old.manifest_set_approvals,
				share_set_approvals: old.share_set_approvals,
			})
		} else {
			result
		}
	}
}
