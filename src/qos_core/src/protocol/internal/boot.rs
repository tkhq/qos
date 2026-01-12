//! Internal boot data types.

use std::{collections::HashSet, fmt};

use qos_p256::P256Public;

use crate::protocol::{Hash256, ProtocolError, QosHash};

/// Enclave configuration specific to AWS Nitro.
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
pub struct NitroConfig {
	/// The hash of the enclave image file
	#[serde(with = "qos_hex::serde")]
	pub pcr0: Vec<u8>,
	/// The hash of the Linux kernel and bootstrap
	#[serde(with = "qos_hex::serde")]
	pub pcr1: Vec<u8>,
	/// The hash of the application
	#[serde(with = "qos_hex::serde")]
	pub pcr2: Vec<u8>,
	/// The hash of the Amazon resource name (ARN) of the IAM role that's
	/// associated with the EC2 instance.
	#[serde(with = "qos_hex::serde")]
	pub pcr3: Vec<u8>,
	/// DER encoded X509 AWS root certificate
	#[serde(with = "qos_hex::serde")]
	pub aws_root_certificate: Vec<u8>,
	/// Reference to the commit QOS was built off of.
	pub qos_commit: String,
}

impl fmt::Debug for NitroConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("NitroConfig")
			.field("pcr0", &qos_hex::encode(&self.pcr0))
			.field("pcr1", &qos_hex::encode(&self.pcr1))
			.field("pcr2", &qos_hex::encode(&self.pcr2))
			.field("pcr3", &qos_hex::encode(&self.pcr3))
			.field("qos_commit", &self.qos_commit)
			.finish_non_exhaustive()
	}
}

/// Policy for restarting the pivot binary.
#[derive(
	PartialEq,
	Eq,
	Clone,
	Copy,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum RestartPolicy {
	/// Never restart the pivot application
	Never,
	/// Always restart the pivot application
	Always,
}

impl fmt::Debug for RestartPolicy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Never => write!(f, "RestartPolicy::Never")?,
			Self::Always => write!(f, "RestartPolicy::Always")?,
		};
		Ok(())
	}
}

#[cfg(any(feature = "mock", test))]
impl Default for RestartPolicy {
	fn default() -> Self {
		Self::Never
	}
}

impl TryFrom<String> for RestartPolicy {
	type Error = ProtocolError;

	fn try_from(s: String) -> Result<RestartPolicy, Self::Error> {
		match s.to_ascii_lowercase().as_str() {
			"never" => Ok(Self::Never),
			"always" => Ok(Self::Always),
			_ => Err(ProtocolError::FailedToParseFromString),
		}
	}
}

/// Pivot binary configuration
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
pub struct PivotConfig {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Arguments to invoke the binary with. Leave this empty if none are
	/// needed.
	pub args: Vec<String>,
}

impl fmt::Debug for PivotConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("PivotConfig")
			.field("hash", &qos_hex::encode(&self.hash))
			.field("restart", &self.restart)
			.field("args", &self.args.join(" "))
			.finish()
	}
}

/// A quorum member's alias and public key.
#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Eq,
	PartialOrd,
	Ord,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct QuorumMember {
	/// A human readable alias to identify the member. The alias is not
	/// cryptographically guaranteed and thus should not be trusted without
	/// verification.
	pub alias: String,
	/// `P256Public` as bytes
	#[serde(with = "qos_hex::serde")]
	pub pub_key: Vec<u8>,
}

impl fmt::Debug for QuorumMember {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("QuorumMember")
			.field("alias", &self.alias)
			.field("pub_key", &qos_hex::encode(&self.pub_key))
			.finish()
	}
}

/// The Manifest Set.
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
pub struct ManifestSet {
	/// The threshold, K, of signatures necessary to have quorum.
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// The set of share keys that can post shares.
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
pub struct ShareSet {
	/// The threshold, K, of signatures necessary to have quorum.
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// A member of a quorum set identified solely by their public key.
#[derive(
	PartialEq,
	PartialOrd,
	Ord,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct MemberPubKey {
	/// Public key of the member
	#[serde(with = "qos_hex::serde")]
	pub pub_key: Vec<u8>,
}

impl fmt::Debug for MemberPubKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MemberPubKey")
			.field("pub_key", &qos_hex::encode(&self.pub_key))
			.finish()
	}
}

/// The set of share keys that can post shares.
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
pub struct PatchSet {
	/// The threshold, K, of signatures necessary to have quorum.
	pub threshold: u32,
	/// Public keys of members composing the set. The length of this, N, must
	/// be gte to the `threshold`, K.
	pub members: Vec<MemberPubKey>,
}

/// A Namespace and its relative nonce.
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
pub struct Namespace {
	/// The namespace. This should be unique relative to other namespaces the
	/// organization running `QuorumOs` has.
	pub name: String,
	/// A monotonically increasing value, used to identify the order in which
	/// manifests for this namespace have been created. This is used to prevent
	/// downgrade attacks - quorum members should only approve a manifest that
	/// has the highest nonce.
	pub nonce: u32,
	/// Quorum Key
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
}

impl fmt::Debug for Namespace {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Namespace")
			.field("name", &self.name)
			.field("nonce", &self.nonce)
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.finish()
	}
}

/// The Manifest for the enclave.
/// NOTE: we currently use JSON format for storing this value.
/// Since we don't have any `HashMap` inside the `Manifest` it works out of the box.
/// If we ever do need a map inside, we should use a `BTreeMap` to ensure keys are sorted.
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
pub struct Manifest {
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfig,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold
	pub patch_set: PatchSet,
	/// Client timeout for calls via the VSOCK/USOCK, defaults to 5s if not specified
	pub client_timeout_ms: Option<u16>,
	/// Pool size argument used to set up our socket pipes, defaults to 1 if not specified
	pub pool_size: Option<u8>,
}

// TODO: remove this once json is the default manifest format
/// The Manifest for the enclave, backwards compatible version 0
#[derive(PartialEq, Eq, Debug, Clone, borsh::BorshDeserialize)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ManifestV0 {
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfig,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold
	pub patch_set: PatchSet,
}

impl From<ManifestV0> for Manifest {
	fn from(old: ManifestV0) -> Self {
		Self {
			namespace: old.namespace,
			pivot: old.pivot,
			manifest_set: old.manifest_set,
			share_set: old.share_set,
			enclave: old.enclave,
			patch_set: old.patch_set,
			pool_size: None,
			client_timeout_ms: None,
		}
	}
}

impl Manifest {
	/// Read a `Manifest` in borsh encoded format from a `u8` buffer, in a backwards compatible way
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		let result = Self::try_from_slice(buf);

		// try loading the old version of manifest
		if result.is_err() {
			let old = ManifestV0::try_from_slice(buf)?;

			Ok(old.into())
		} else {
			result
		}
	}
}

/// An approval by a Quorum Member.
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
pub struct Approval {
	/// Quorum Member's signature.
	#[serde(with = "qos_hex::serde")]
	pub signature: Vec<u8>,
	/// Description of the Quorum Member
	pub member: QuorumMember,
}

impl fmt::Debug for Approval {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Approval")
			.field("signature", &qos_hex::encode(&self.signature))
			.field("member", &self.member)
			.finish()
	}
}

impl Approval {
	/// Verify that the approval is a valid a signature for the given `msg`.
	pub(crate) fn verify(&self, msg: &[u8]) -> Result<(), ProtocolError> {
		let pub_key = P256Public::from_bytes(&self.member.pub_key)?;

		if pub_key.verify(msg, &self.signature).is_ok() {
			Ok(())
		} else {
			Err(ProtocolError::CouldNotVerifyApproval)
		}
	}
}

/// [`Manifest`] with accompanying [`Approval`]s.
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
pub struct ManifestEnvelope {
	/// Encapsulated manifest.
	pub manifest: Manifest,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	///  Approvals for [`Self::manifest`] from the share set. This is primarily
	/// used to audit what share holders provisioned the quorum key.
	pub share_set_approvals: Vec<Approval>,
}

/// [`ManifestV0`] with accompanying [`Approval`]s.
#[derive(PartialEq, Eq, Debug, Clone, borsh::BorshDeserialize)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ManifestEnvelopeV0 {
	/// Encapsulated manifest.
	pub manifest: ManifestV0,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	///  Approvals for [`Self::manifest`] from the share set. This is primarily
	/// used to audit what share holders provisioned the quorum key.
	pub share_set_approvals: Vec<Approval>,
}

impl ManifestEnvelope {
	/// Check if the encapsulated manifest has K valid approvals from the
	/// manifest approval set.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		let mut uniq_members = HashSet::new();
		for approval in &self.manifest_set_approvals {
			let member_pub_key =
				P256Public::from_bytes(&approval.member.pub_key)?;

			// Ensure that this is a valid signature from the member
			let is_valid_signature = member_pub_key
				.verify(&self.manifest.qos_hash(), &approval.signature)
				.is_ok();
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}

			// Ensure that this member belongs to the manifest set
			if !self.manifest.manifest_set.members.contains(&approval.member) {
				return Err(ProtocolError::NotManifestSetMember);
			}

			// Ensure that the member only has 1 approval. Note that we don't
			// include the signature in this check because the signature is
			// malleable. i.e. there could be two different signatures per
			// member.
			if !uniq_members.insert(approval.member.qos_hash()) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}

		// Ensure that there are at least threshold unique members who approved
		if uniq_members.len() < self.manifest.manifest_set.threshold as usize {
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}
	/// Read a `ManifestEnvelope` from a `u8` buffer, in a backwards compatible way
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		let result = Self::try_from_slice(buf);

		// try loading the old version of manifest
		if result.is_err() {
			let old = ManifestEnvelopeV0::try_from_slice(buf)?;

			Ok(Self {
				manifest: Manifest::from(old.manifest),
				manifest_set_approvals: old.manifest_set_approvals,
				share_set_approvals: old.share_set_approvals,
			})
		} else {
			result
		}
	}
}
