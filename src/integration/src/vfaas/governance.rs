//! Artifact governance: quorum approval of WASM artifacts and of the
//! program→policy bindings ([`Ruleset`]) that gate them.
//!
//! Reuses the real QOS quorum primitives ([`ManifestSet`], [`Approval`],
//! `QuorumMember`) so approving a WASM artifact works exactly like approving
//! a manifest: K-of-N members sign the artifact descriptor hash. The pivot
//! is launched with a Borsh-serialized [`ManifestSet`] and accepts only
//! artifacts whose envelopes verify against it.

use std::collections::HashSet;
use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::protocol::services::boot::{Approval, ManifestSet, QuorumMember};
use qos_crypto::sha_256;
use qos_p256::{P256Pair, P256Public};
use vfaas_abi::{PolicyHash, ProgramHash, VFAAS_ABI_VERSION};

/// What kind of artifact a descriptor describes. The kind is part of the
/// signed descriptor, so a blob approved as a policy can never be invoked
/// as a program (or vice versa).
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
pub enum ArtifactKind {
	/// An executable program (`__vfaas_execute` entry point).
	Function,
	/// A policy gating program execution (`__vfaas_evaluate` entry point).
	Policy,
}

/// Descriptor of a WASM artifact. This whole struct — not just the blob
/// hash — is what quorum members approve: name, version, kind, ABI version,
/// metadata, and resource budget are all signature-bound.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
	/// Function or policy.
	pub kind: ArtifactKind,
	/// Human-readable artifact name (e.g. `"reverse"`).
	pub name: String,
	/// Artifact version string (e.g. `"0.1.0"`).
	pub version: String,
	/// SHA-256 of the WASM blob.
	pub wasm_hash: [u8; 32],
	/// The guest ABI version the artifact targets.
	pub abi_version: u32,
	/// SHA-256 of free-form artifact metadata.
	pub metadata_hash: [u8; 32],
	/// Fuel budget for each execution of this artifact. `None` means the
	/// engine default. Part of the signed descriptor: resource budgets are
	/// approved per artifact, not set unilaterally by the caller.
	pub fuel_budget: Option<u64>,
}

impl Artifact {
	/// Build a descriptor for `wasm`, hashing the blob and metadata and
	/// stamping the current [`VFAAS_ABI_VERSION`].
	pub fn new(
		kind: ArtifactKind,
		name: impl Into<String>,
		version: impl Into<String>,
		wasm: &[u8],
		metadata: &[u8],
		fuel_budget: Option<u64>,
	) -> Self {
		Self {
			kind,
			name: name.into(),
			version: version.into(),
			wasm_hash: sha_256(wasm),
			abi_version: VFAAS_ABI_VERSION,
			metadata_hash: sha_256(metadata),
			fuel_budget,
		}
	}

	/// The message quorum members sign: SHA-256 of the Borsh-serialized
	/// descriptor.
	#[must_use]
	pub fn approval_payload_hash(&self) -> [u8; 32] {
		sha_256(&borsh::to_vec(self).expect("artifact serializes"))
	}
}

/// An artifact descriptor plus the quorum approvals over it.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct ArtifactEnvelope {
	/// The approved descriptor.
	pub artifact: Artifact,
	/// Quorum member signatures over [`Artifact::approval_payload_hash`].
	pub approvals: Vec<Approval>,
}

/// Domain-separation prefix for ruleset approval payloads, so a member's
/// signature over a ruleset can never double as a signature over an
/// artifact descriptor (whose payload is the bare descriptor hash), or vice
/// versa.
const RULESET_APPROVAL_DOMAIN: &[u8] = b"vfaas-ruleset-v1";

/// A binding of a program to the policy that gates every execution of it.
///
/// Like an [`Artifact`] descriptor, the binding itself is what quorum
/// members sign: which policy governs which program is a quorum decision
/// made at registration, never a caller choice made at execute time.
/// Rebinding a program to a different policy takes a fresh quorum-approved
/// ruleset.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct Ruleset {
	/// The program being bound.
	pub program: ProgramHash,
	/// The policy that gates the program.
	pub policy: PolicyHash,
}

impl Ruleset {
	/// The message quorum members sign: SHA-256 of the domain-prefixed
	/// Borsh-serialized binding.
	#[must_use]
	pub fn approval_payload_hash(&self) -> [u8; 32] {
		let mut bytes = RULESET_APPROVAL_DOMAIN.to_vec();
		bytes.extend(borsh::to_vec(self).expect("ruleset serializes"));
		sha_256(&bytes)
	}
}

/// A ruleset plus the quorum approvals over it.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct RulesetEnvelope {
	/// The approved binding.
	pub ruleset: Ruleset,
	/// Quorum member signatures over [`Ruleset::approval_payload_hash`].
	pub approvals: Vec<Approval>,
}

/// Why envelope verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
	/// The artifact set threshold is zero, which would approve anything.
	ZeroThreshold,
	/// An approval came from a key that is not in the artifact set.
	NotAMember {
		/// Alias of the claimed member.
		alias: String,
	},
	/// An approver's public key bytes could not be parsed.
	InvalidApproverKey {
		/// Alias of the member with the malformed key.
		alias: String,
	},
	/// An approval signature did not verify over the descriptor hash.
	InvalidSignature {
		/// Alias of the member whose signature failed.
		alias: String,
	},
	/// The same member approved more than once.
	DuplicateApprover {
		/// Alias of the duplicated member.
		alias: String,
	},
	/// Fewer distinct valid approvals than the threshold requires.
	InsufficientApprovals {
		/// Distinct valid approvals present.
		got: usize,
		/// Approvals required by the artifact set.
		need: u32,
	},
}

impl fmt::Display for GovernanceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ZeroThreshold => {
				write!(
					f,
					"artifact approval threshold must be greater than zero"
				)
			}
			Self::NotAMember { alias } => {
				write!(f, "approval from non-member {alias}")
			}
			Self::InvalidApproverKey { alias } => {
				write!(f, "invalid approver public key for {alias}")
			}
			Self::InvalidSignature { alias } => {
				write!(f, "invalid approval signature from {alias}")
			}
			Self::DuplicateApprover { alias } => {
				write!(f, "duplicate approval from {alias}")
			}
			Self::InsufficientApprovals { got, need } => {
				write!(
					f,
					"not enough artifact approvals: got {got}, need {need}"
				)
			}
		}
	}
}

impl std::error::Error for GovernanceError {}

/// Verify that `envelope` carries at least `artifact_set.threshold` distinct,
/// valid member approvals over the artifact descriptor.
///
/// # Errors
///
/// Returns a [`GovernanceError`] describing the first check that failed.
pub fn verify_artifact_envelope(
	envelope: &ArtifactEnvelope,
	artifact_set: &ManifestSet,
) -> Result<(), GovernanceError> {
	verify_approvals(
		&envelope.artifact.approval_payload_hash(),
		&envelope.approvals,
		artifact_set,
	)
}

/// Verify that `envelope` carries at least `artifact_set.threshold` distinct,
/// valid member approvals over the program→policy binding.
///
/// # Errors
///
/// Returns a [`GovernanceError`] describing the first check that failed.
pub fn verify_ruleset_envelope(
	envelope: &RulesetEnvelope,
	artifact_set: &ManifestSet,
) -> Result<(), GovernanceError> {
	verify_approvals(
		&envelope.ruleset.approval_payload_hash(),
		&envelope.approvals,
		artifact_set,
	)
}

/// The shared K-of-N check: membership, signature over `payload_hash`,
/// duplicate rejection, threshold.
fn verify_approvals(
	payload_hash: &[u8; 32],
	approvals: &[Approval],
	artifact_set: &ManifestSet,
) -> Result<(), GovernanceError> {
	if artifact_set.threshold == 0 {
		return Err(GovernanceError::ZeroThreshold);
	}

	let mut unique_approvers = HashSet::new();

	for approval in approvals {
		if !artifact_set.members.contains(&approval.member) {
			return Err(GovernanceError::NotAMember {
				alias: approval.member.alias.clone(),
			});
		}

		let public_key = P256Public::from_bytes(&approval.member.pub_key)
			.map_err(|_| GovernanceError::InvalidApproverKey {
				alias: approval.member.alias.clone(),
			})?;

		public_key.verify(payload_hash, &approval.signature).map_err(|_| {
			GovernanceError::InvalidSignature {
				alias: approval.member.alias.clone(),
			}
		})?;

		if !unique_approvers.insert(approval.member.pub_key.clone()) {
			return Err(GovernanceError::DuplicateApprover {
				alias: approval.member.alias.clone(),
			});
		}
	}

	if unique_approvers.len() < artifact_set.threshold as usize {
		return Err(GovernanceError::InsufficientApprovals {
			got: unique_approvers.len(),
			need: artifact_set.threshold,
		});
	}

	Ok(())
}

/// Sign an artifact descriptor as `member`, producing an [`Approval`] for
/// its envelope. Used by tooling and tests; the pivot only ever verifies.
///
/// # Panics
///
/// Panics if signing fails, which indicates an unusable key pair.
#[must_use]
pub fn approve_artifact(
	artifact: &Artifact,
	pair: &P256Pair,
	member: QuorumMember,
) -> Approval {
	Approval {
		signature: pair
			.sign(&artifact.approval_payload_hash())
			.expect("P256 signing is infallible with a valid pair"),
		member,
	}
}

/// Sign a program→policy binding as `member`, producing an [`Approval`] for
/// its [`RulesetEnvelope`]. Used by tooling and tests; the pivot only ever
/// verifies.
///
/// # Panics
///
/// Panics if signing fails, which indicates an unusable key pair.
#[must_use]
pub fn approve_ruleset(
	ruleset: &Ruleset,
	pair: &P256Pair,
	member: QuorumMember,
) -> Approval {
	Approval {
		signature: pair
			.sign(&ruleset.approval_payload_hash())
			.expect("P256 signing is infallible with a valid pair"),
		member,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn member(alias: &str, pair: &P256Pair) -> QuorumMember {
		QuorumMember {
			alias: alias.into(),
			pub_key: pair.public_key().to_bytes(),
		}
	}

	fn test_artifact() -> Artifact {
		Artifact::new(
			ArtifactKind::Function,
			"reverse",
			"0.1.0",
			b"wasm",
			b"meta",
			None,
		)
	}

	#[test]
	fn threshold_approvals_verify() {
		let pair1 = P256Pair::generate().unwrap();
		let pair2 = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let member2 = member("user2", &pair2);
		let set = ManifestSet {
			threshold: 2,
			members: vec![member1.clone(), member2.clone()],
		};
		let artifact = test_artifact();
		let envelope = ArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				approve_artifact(&artifact, &pair1, member1),
				approve_artifact(&artifact, &pair2, member2),
			],
		};

		assert_eq!(verify_artifact_envelope(&envelope, &set), Ok(()));
	}

	#[test]
	fn duplicate_approver_is_rejected() {
		let pair = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair);
		let set = ManifestSet { threshold: 2, members: vec![member1.clone()] };
		let artifact = test_artifact();
		let envelope = ArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				approve_artifact(&artifact, &pair, member1.clone()),
				approve_artifact(&artifact, &pair, member1),
			],
		};

		assert_eq!(
			verify_artifact_envelope(&envelope, &set),
			Err(GovernanceError::DuplicateApprover { alias: "user1".into() })
		);
	}

	#[test]
	fn insufficient_approvals_are_rejected() {
		let pair1 = P256Pair::generate().unwrap();
		let pair2 = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let member2 = member("user2", &pair2);
		let set = ManifestSet {
			threshold: 2,
			members: vec![member1.clone(), member2],
		};
		let artifact = test_artifact();
		let envelope = ArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![approve_artifact(&artifact, &pair1, member1)],
		};

		assert_eq!(
			verify_artifact_envelope(&envelope, &set),
			Err(GovernanceError::InsufficientApprovals { got: 1, need: 2 })
		);
	}

	#[test]
	fn non_member_approval_is_rejected() {
		let pair1 = P256Pair::generate().unwrap();
		let outsider = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let set = ManifestSet { threshold: 1, members: vec![member1] };
		let artifact = test_artifact();
		let envelope = ArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![approve_artifact(
				&artifact,
				&outsider,
				member("mallory", &outsider),
			)],
		};

		assert_eq!(
			verify_artifact_envelope(&envelope, &set),
			Err(GovernanceError::NotAMember { alias: "mallory".into() })
		);
	}

	#[test]
	fn signature_over_different_descriptor_is_rejected() {
		let pair = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair);
		let set = ManifestSet { threshold: 1, members: vec![member1.clone()] };
		let artifact = test_artifact();
		// Approve a different descriptor (same blob, different fuel budget),
		// then present that approval for `artifact`.
		let other = Artifact { fuel_budget: Some(9), ..artifact.clone() };
		let envelope = ArtifactEnvelope {
			artifact,
			approvals: vec![approve_artifact(&other, &pair, member1)],
		};

		assert_eq!(
			verify_artifact_envelope(&envelope, &set),
			Err(GovernanceError::InvalidSignature { alias: "user1".into() })
		);
	}

	#[test]
	fn zero_threshold_is_rejected() {
		let set = ManifestSet { threshold: 0, members: vec![] };
		let artifact = test_artifact();
		let envelope = ArtifactEnvelope { artifact, approvals: vec![] };

		assert_eq!(
			verify_artifact_envelope(&envelope, &set),
			Err(GovernanceError::ZeroThreshold)
		);
	}

	fn test_ruleset() -> Ruleset {
		Ruleset {
			program: ProgramHash::new([1u8; 32]),
			policy: PolicyHash::new([2u8; 32]),
		}
	}

	#[test]
	fn ruleset_threshold_approvals_verify() {
		let pair1 = P256Pair::generate().unwrap();
		let pair2 = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let member2 = member("user2", &pair2);
		let set = ManifestSet {
			threshold: 2,
			members: vec![member1.clone(), member2.clone()],
		};
		let ruleset = test_ruleset();
		let envelope = RulesetEnvelope {
			ruleset,
			approvals: vec![
				approve_ruleset(&ruleset, &pair1, member1),
				approve_ruleset(&ruleset, &pair2, member2),
			],
		};

		assert_eq!(verify_ruleset_envelope(&envelope, &set), Ok(()));
	}

	#[test]
	fn ruleset_insufficient_approvals_are_rejected() {
		let pair1 = P256Pair::generate().unwrap();
		let pair2 = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let member2 = member("user2", &pair2);
		let set = ManifestSet {
			threshold: 2,
			members: vec![member1.clone(), member2],
		};
		let ruleset = test_ruleset();
		let envelope = RulesetEnvelope {
			ruleset,
			approvals: vec![approve_ruleset(&ruleset, &pair1, member1)],
		};

		assert_eq!(
			verify_ruleset_envelope(&envelope, &set),
			Err(GovernanceError::InsufficientApprovals { got: 1, need: 2 })
		);
	}

	#[test]
	fn ruleset_approval_binds_both_hashes() {
		let pair = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair);
		let set = ManifestSet { threshold: 1, members: vec![member1.clone()] };
		// Approve a binding to one policy, then present the approval for a
		// binding to a different policy.
		let approved = test_ruleset();
		let presented =
			Ruleset { policy: PolicyHash::new([9u8; 32]), ..approved };
		let envelope = RulesetEnvelope {
			ruleset: presented,
			approvals: vec![approve_ruleset(&approved, &pair, member1)],
		};

		assert_eq!(
			verify_ruleset_envelope(&envelope, &set),
			Err(GovernanceError::InvalidSignature { alias: "user1".into() })
		);
	}

	#[test]
	fn artifact_approval_is_not_a_ruleset_approval() {
		// Same signer, but artifact and ruleset payloads are domain-separated
		// — an artifact approval presented for a ruleset must fail.
		let pair = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair);
		let set = ManifestSet { threshold: 1, members: vec![member1.clone()] };
		let envelope = RulesetEnvelope {
			ruleset: test_ruleset(),
			approvals: vec![approve_artifact(&test_artifact(), &pair, member1)],
		};

		assert_eq!(
			verify_ruleset_envelope(&envelope, &set),
			Err(GovernanceError::InvalidSignature { alias: "user1".into() })
		);
	}
}
