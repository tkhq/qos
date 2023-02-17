//! Standard boot logic and types.

use std::fmt;

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	services::attestation, Hash256, ProtocolError, ProtocolState, QosHash,
};

/// Enclave configuration specific to AWS Nitro.
#[derive(
	PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct NitroConfig {
	/// The hash of the enclave image file
	pub pcr0: Vec<u8>,
	/// The hash of the Linux kernel and bootstrap
	pub pcr1: Vec<u8>,
	/// The hash of the application
	pub pcr2: Vec<u8>,
	/// The hash of the Amazon resource name (ARN) of the IAM role that's
	/// associated with the EC2 instance.
	pub pcr3: Vec<u8>,
	/// DER encoded X509 AWS root certificate
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
	PartialEq, Eq, Clone, Copy, borsh::BorshSerialize, borsh::BorshDeserialize,
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
	PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotConfig {
	/// Reference to the commit the pivot was built off of.
	pub commit: String,
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
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
			.field("commit", &self.commit)
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
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct QuorumMember {
	/// A human readable alias to identify the member. The alias is not
	/// cryptographically guaranteed and thus should not be trusted without
	/// verification.
	pub alias: String,
	/// P256Public as bytes
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
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ManifestSet {
	/// The threshold, K, of signatures necessary to have  quorum.
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// The set of share keys that can post shares.
#[derive(
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ShareSet {
	/// The threshold, K, of signatures necessary to have  quorum.
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// A Namespace and its relative nonce.
#[derive(
	PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct Namespace {
	/// The namespace. This should be unique relative to other namespaces the
	/// organization running QuorumOs has.
	pub name: String,
	/// A monotonically increasing value, used to identify the order in which
	/// manifests for this namespace have been created. This is used to prevent
	/// downgrade attacks - quorum members should only approve a manifest that
	/// has the highest nonce.
	pub nonce: u32,
	/// Quorum Key
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
#[derive(
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
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
}

/// An approval by a Quorum Member.
#[derive(
	PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct Approval {
	/// Quorum Member's signature.
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
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
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

impl ManifestEnvelope {
	/// Check if the encapsulated manifest has K valid approvals from the
	/// manifest approval set.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		for approval in &self.manifest_set_approvals {
			let pub_key = P256Public::from_bytes(&approval.member.pub_key)?;

			let is_valid_signature = pub_key
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
		}

		if self.manifest_set_approvals.len()
			< self.manifest.manifest_set.threshold as usize
		{
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}
}

pub(in crate::protocol::services) fn put_manifest_and_pivot(
	state: &mut ProtocolState,
	manifest_envelope: &ManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	manifest_envelope.check_approvals()?;
	if !manifest_envelope.share_set_approvals.is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}
	if sha_256(pivot) != manifest_envelope.manifest.pivot.hash {
		return Err(ProtocolError::InvalidPivotHash);
	};

	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;
	state.handles.put_pivot(pivot)?;
	state.handles.put_manifest_envelope(manifest_envelope)?;

	let nsm_response = attestation::get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_key.public_key().to_bytes(),
		manifest_envelope.manifest.qos_hash().to_vec(),
	);

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
	use std::{ops::Deref, path::Path};

	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{handles::Handles, io::SocketAddress};

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
			(member1_pair, quorum_members.get(0).unwrap().clone()),
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
				commit: "commit lord".to_string(),
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
			},
			manifest_set: ManifestSet { threshold: 2, members: quorum_members },
			share_set: ShareSet { threshold: 2, members: vec![] },
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
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles.clone(),
			SocketAddress::new_unix("./never.sock"),
		);

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
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles.clone(),
			SocketAddress::new_unix("./never.sock"),
		);

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
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles.clone(),
			SocketAddress::new_unix("./never.sock"),
		);

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
			(*ephemeral_file.deref()).to_string(),
			"quorum_key".to_string(),
			(*manifest_file.deref()).to_string(),
			(*pivot_file.deref()).to_string(),
		);
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles,
			SocketAddress::new_unix("./never.sock"),
		);

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
			let mut approval = approvals.get_mut(0).unwrap();
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
			(*ephemeral_file.deref()).to_string(),
			"quorum_key".to_string(),
			(*manifest_file.deref()).to_string(),
			(*pivot_file.deref()).to_string(),
		);
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles,
			SocketAddress::new_unix("./never.sock"),
		);

		let error =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap_err();

		assert_eq!(error, ProtocolError::NotManifestSetMember);

		assert!(!Path::new(&*pivot_file).exists());
		assert!(!Path::new(&*ephemeral_file).exists());
		assert!(!Path::new(&*manifest_file).exists());
	}
}
