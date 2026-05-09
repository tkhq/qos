//! Original legacy manifest schema (v0).

use std::fmt;

use qos_p256::P256Public;

use crate::protocol::{Hash256, ProtocolError};

use super::shared;

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
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub enum RestartPolicy {
	/// Never restart the pivot application
	#[cfg_attr(any(feature = "mock", test), default)]
	Never,
	/// Always restart the pivot application
	Always,
}

impl fmt::Debug for RestartPolicy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Never => write!(f, "RestartPolicy::Never")?,
			Self::Always => write!(f, "RestartPolicy::Always")?,
		}
		Ok(())
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
	#[serde(with = "qos_json::string_or_numeric")]
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
	#[serde(with = "qos_json::string_or_numeric")]
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
	#[serde(with = "qos_json::string_or_numeric")]
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
	/// manifests for this namespace have been created.
	#[serde(with = "qos_json::string_or_numeric")]
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

/// Pivot binary configuration, original version (v0).
#[derive(
	PartialEq,
	Eq,
	Clone,
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotConfigV0 {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Arguments to invoke the binary with. Leave this empty if none are
	/// needed.
	pub args: Vec<String>,
}

/// The original legacy manifest (v0).
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
pub struct ManifestV0 {
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfigV0,
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set members and threshold
	pub share_set: ShareSet,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// Patch set members and threshold
	pub patch_set: PatchSet,
}

/// [`ManifestV0`] with accompanying [`Approval`]s.
pub type ManifestEnvelopeV0 = shared::ManifestEnvelope<ManifestV0>;
