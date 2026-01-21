//! Standard boot logic and types.

use std::{collections::HashSet, fmt};

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	services::attestation, Hash256, ProtocolError, ProtocolState, QosHash,
};

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

/// Pivot bridge host configuration
#[derive(
	PartialEq,
	Eq,
	Clone,
	serde::Serialize,
	serde::Deserialize,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum BridgeConfig {
	/// Server hosting bridge, connections go INTO the enclave app on given port and host ip string
	Server(u16, String),
	/// Client connecting bridge, connections go OUT of the enclave app via given port, connecting
	/// to the provided hostname. If `None` it will use the transparent protocol.
	/// *NOTE*: currently unimplemented and results in boot panic if set
	Client(u16, Option<String>),
}

impl Default for BridgeConfig {
	fn default() -> Self {
		Self::Server(DEFAULT_APP_HOST_PORT, DEFAULT_APP_HOST_IP.into())
	}
}

impl BridgeConfig {
	/// Helper to extract port from either variant
	pub fn port(&self) -> u16 {
		match self {
			Self::Server(port, _) | Self::Client(port, _) => *port,
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
	/// Bridge host configuration for the pivot is a set of per-port rules.
	/// If set the pivot will service TCP with the provided ports and a bridge will provide the TCP -> VSOCK -> TCP streams.
	/// If not set the pivot will service VSOCK and the host side needs to be provided manually.
	pub bridge_config: Vec<BridgeConfig>,
	/// Arguments to invoke the binary with. Leave this empty if none are
	/// needed.
	pub args: Vec<String>,
}

/// Pivot binary configuration, original version (V0)
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

impl From<PivotConfigV0> for PivotConfig {
	fn from(value: PivotConfigV0) -> Self {
		Self {
			hash: value.hash,
			restart: value.restart,
			args: value.args,
			bridge_config: Vec::new(),
		}
	}
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

/// Default port to use for host bridge in server mode
pub const DEFAULT_APP_HOST_PORT: u16 = 3000;
/// Default host ip string for host bridge in server mode
pub const DEFAULT_APP_HOST_IP: &str = "0.0.0.0";

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
}

// TODO: remove this once json is the default manifest format
/// The Manifest for the enclave, backwards compatible version 0
#[derive(
	PartialEq, Eq, Debug, Clone, borsh::BorshDeserialize, serde::Deserialize,
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

impl From<ManifestV0> for Manifest {
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

impl Manifest {
	/// Read a `Manifest` in a backwards compatible way
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, borsh::io::Error> {
		use borsh::BorshDeserialize;

		// try old version with json format
		if let Ok(v0) = serde_json::from_slice::<ManifestV0>(buf) {
			return Ok(v0.into());
		};

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

pub(in crate::protocol::services) fn put_manifest_and_pivot(
	state: &mut ProtocolState,
	manifest_envelope: &ManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	// 1. Check signatures over the manifest envelope.
	manifest_envelope.check_approvals()?;
	if !manifest_envelope.share_set_approvals.is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}
	let actual_hash = sha_256(pivot);
	let expected_hash = manifest_envelope.manifest.pivot.hash;
	if actual_hash != expected_hash {
		return Err(ProtocolError::InvalidPivotHash {
			expected: qos_hex::encode(&expected_hash),
			actual: qos_hex::encode(&actual_hash),
		});
	};

	// 2. Generate an Ephemeral Key.
	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;
	state.handles.put_pivot(pivot)?;
	state.handles.put_manifest_envelope(manifest_envelope)?;

	// 3. Make an attestation request, placing the manifest hash in the
	// `user_data` field and the Ephemeral Key public key in the `public_key`
	// field.
	let nsm_response = attestation::get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_key.public_key().to_bytes(),
		manifest_envelope.manifest.qos_hash().to_vec(),
	);

	// 4. Return the NSM Response containing COSE Sign1 encoded attestation
	// document.
	Ok(nsm_response)
}

pub(in crate::protocol) fn boot_standard(
	state: &mut ProtocolState,
	manifest_envelope: &ManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	let nsm_response = put_manifest_and_pivot(state, manifest_envelope, pivot)?;
	Ok(nsm_response)
}

#[cfg(test)]
mod test {
	use std::path::Path;

	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::handles::Handles;

	fn get_manifest() -> (Manifest, Vec<(P256Pair, QuorumMember)>, Vec<u8>) {
		let quorum_pair = P256Pair::generate().unwrap();
		let member1_pair = P256Pair::generate().unwrap();
		let member2_pair = P256Pair::generate().unwrap();
		let member3_pair = P256Pair::generate().unwrap();

		let pivot = b"this is a pivot binary".to_vec();

		let quorum_members = vec![
			QuorumMember {
				alias: "member1".to_string(),
				pub_key: member1_pair.public_key().to_bytes(),
			},
			QuorumMember {
				alias: "member2".to_string(),
				pub_key: member2_pair.public_key().to_bytes(),
			},
			QuorumMember {
				alias: "member3".to_string(),
				pub_key: member3_pair.public_key().to_bytes(),
			},
		];

		let member_with_keys = vec![
			(member1_pair, quorum_members.first().unwrap().clone()),
			(member2_pair, quorum_members.get(1).unwrap().clone()),
			(member3_pair, quorum_members.get(2).unwrap().clone()),
		];

		let manifest = Manifest {
			namespace: Namespace {
				nonce: 420,
				name: "vape lord".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			},
			pivot: PivotConfig {
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
				..Default::default()
			},
			manifest_set: ManifestSet { threshold: 2, members: quorum_members },
			share_set: ShareSet { threshold: 2, members: vec![] },
			..Default::default()
		};

		(manifest, member_with_keys, pivot)
	}

	#[test]
	fn manifest_hash() {
		let (manifest, _members, _pivot) = get_manifest();

		let hashes: Vec<_> = (0..10).map(|_| manifest.qos_hash()).collect();
		let is_valid = (1..10).all(|i| hashes[i] == hashes[0]);
		assert!(is_valid);
	}

	#[test]
	fn boot_standard_accepts_approved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let approvals = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_accepts_approved_manifest.pivot".to_string();
		let ephemeral_file =
			"boot_standard_accepts_approved_manifest_eph.secret".to_string();
		let manifest_file =
			"boot_standard_accepts_approved_manifest.manifest".to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file.clone(),
			pivot_file.clone(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let _nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap();

		assert!(Path::new(&pivot_file).exists());
		assert!(Path::new(&ephemeral_file).exists());

		assert_eq!(handles.get_manifest_envelope().unwrap(), manifest_envelope);

		std::fs::remove_file(pivot_file).unwrap();
		std::fs::remove_file(ephemeral_file).unwrap();
		std::fs::remove_file(manifest_file).unwrap();
	}

	#[test]
	fn boot_standard_rejects_manifest_if_not_enough_approvals() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let approvals = members
				[0usize..manifest.manifest_set.threshold as usize - 1]
				.iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: member.clone(),
				})
				.collect();

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.pivot"
				.to_string();
		let ephemeral_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.secret"
				.to_string();
		let manifest_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.manifest"
				.to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file,
			pivot_file,
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot);

		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
		assert!(!Path::new(&ephemeral_file).exists());
		assert!(nsm_resposne.is_err());
	}

	#[test]
	fn boot_standard_rejects_unapproved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let approvals = members
				.into_iter()
				.map(|(_pair, member)| Approval {
					signature: vec![0, 0],
					member,
				})
				.collect();

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_rejects_unapproved_manifest.pivot".to_string();
		let ephemeral_file =
			"boot_standard_rejects_unapproved_manifest.secret".to_string();
		let manifest_file =
			"boot_standard_rejects_unapproved_manifest.manifest".to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file,
			pivot_file,
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot);

		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
		assert!(!Path::new(&ephemeral_file).exists());
		assert!(nsm_resposne.is_err());
	}

	#[test]
	fn boot_standard_rejects_manifest_envelope_with_share_set_approvals() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![approvals.remove(0)],
			}
		};

		let pivot_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals.pivot".into();
		let ephemeral_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals_eph.secret".into();
		let manifest_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			"quorum_key".to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles, None);

		let error =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap_err();

		assert_eq!(error, ProtocolError::BadShareSetApprovals);

		assert!(!Path::new(&*pivot_file).exists());
		assert!(!Path::new(&*ephemeral_file).exists());
		assert!(!Path::new(&*manifest_file).exists());
	}

	#[test]
	fn boot_standard_rejects_approval_from_non_manifest_set_member() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			// Change a member so that are not recognized as part of the
			// manifest set.
			let approval = approvals.get_mut(0).unwrap();
			let pair = P256Pair::generate().unwrap();
			approval.member.pub_key = pair.public_key().to_bytes();
			approval.signature = pair.sign(&manifest.qos_hash()).unwrap();

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![],
			}
		};

		let pivot_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.pivot"
				.into();
		let ephemeral_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.secret".into();
		let manifest_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			"quorum_key".to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles, None);

		let error =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap_err();

		assert_eq!(error, ProtocolError::NotManifestSetMember);

		assert!(!Path::new(&*pivot_file).exists());
		assert!(!Path::new(&*ephemeral_file).exists());
		assert!(!Path::new(&*manifest_file).exists());
	}

	#[test]
	fn check_approvals_rejects_duplicates() {
		let (manifest, members, ..) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			// Just make 1 approval
			let mut approvals: Vec<_> = members[..1]
				.iter()
				.cloned()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			// Duplicate the approval and add it
			let duplicate_approval = approvals[0].clone();
			approvals.push(duplicate_approval);

			ManifestEnvelope {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![],
			}
		};

		let err = manifest_envelope.check_approvals().unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateApproval);
	}

	#[test]
	fn try_from_slice_compat_works() {
		let bytes = std::fs::read("./fixtures/old_manifest").unwrap();

		let manifest = Manifest::try_from_slice_compat(&bytes).unwrap();

		assert_eq!(manifest.namespace.name, "quit-coding-to-vape");
		assert_eq!(manifest.pivot.bridge_config.len(), 0);
	}
}
