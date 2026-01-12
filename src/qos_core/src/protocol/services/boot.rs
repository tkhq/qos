//! Standard boot logic and types.

use std::collections::HashSet;

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};
use qos_proto::ProtoHash;

use crate::protocol::{services::attestation, ProtocolError, ProtocolState};

pub use qos_proto::{
	Approval, Manifest, ManifestEnvelope, ManifestSet, MemberPubKey, Namespace,
	NitroConfig, PatchSet, PivotConfig, QuorumMember, RestartPolicy, ShareSet,
};

/// Convert internal `qos_nsm::types::NsmResponse` to proto `qos_proto::NsmResponse`.
pub fn nsm_response_to_proto(response: NsmResponse) -> qos_proto::NsmResponse {
	use qos_proto::nsm_response::Response;

	let inner = match response {
		NsmResponse::DescribePCR { lock, data } => {
			Response::DescribePcr(qos_proto::DescribePcrResponse { lock, data })
		}
		NsmResponse::ExtendPCR { data } => {
			Response::ExtendPcr(qos_proto::ExtendPcrResponse { data })
		}
		NsmResponse::LockPCR => {
			Response::LockPcr(qos_proto::LockPcrResponse {})
		}
		NsmResponse::LockPCRs => {
			Response::LockPcrs(qos_proto::LockPcrsResponse {})
		}
		NsmResponse::DescribeNSM {
			version_major,
			version_minor,
			version_patch,
			module_id,
			max_pcrs,
			locked_pcrs,
			digest,
		} => {
			let proto_digest = match digest {
				qos_nsm::types::NsmDigest::SHA256 => qos_proto::NsmDigest::Sha256,
				qos_nsm::types::NsmDigest::SHA384 => qos_proto::NsmDigest::Sha384,
				qos_nsm::types::NsmDigest::SHA512 => qos_proto::NsmDigest::Sha512,
			};
			Response::DescribeNsm(qos_proto::DescribeNsmResponse {
				version_major: version_major as u32,
				version_minor: version_minor as u32,
				version_patch: version_patch as u32,
				module_id,
				max_pcrs: max_pcrs as u32,
				locked_pcrs: locked_pcrs.into_iter().map(|x| x as u32).collect(),
				digest: proto_digest as i32,
			})
		}
		NsmResponse::Attestation { document } => {
			Response::Attestation(qos_proto::AttestationResponse { document })
		}
		NsmResponse::GetRandom { random } => {
			Response::GetRandom(qos_proto::GetRandomResponse { random })
		}
		NsmResponse::Error(code) => {
			let proto_code = match code {
				qos_nsm::types::NsmErrorCode::Success => {
					qos_proto::NsmErrorCode::Success
				}
				qos_nsm::types::NsmErrorCode::InvalidArgument => {
					qos_proto::NsmErrorCode::InvalidArgument
				}
				qos_nsm::types::NsmErrorCode::InvalidIndex => {
					qos_proto::NsmErrorCode::InvalidIndex
				}
				qos_nsm::types::NsmErrorCode::InvalidResponse => {
					qos_proto::NsmErrorCode::InvalidResponse
				}
				qos_nsm::types::NsmErrorCode::ReadOnlyIndex => {
					qos_proto::NsmErrorCode::ReadOnlyIndex
				}
				qos_nsm::types::NsmErrorCode::InvalidOperation => {
					qos_proto::NsmErrorCode::InvalidOperation
				}
				qos_nsm::types::NsmErrorCode::BufferTooSmall => {
					qos_proto::NsmErrorCode::BufferTooSmall
				}
				qos_nsm::types::NsmErrorCode::InputTooLarge => {
					qos_proto::NsmErrorCode::InputTooLarge
				}
				qos_nsm::types::NsmErrorCode::InternalError => {
					qos_proto::NsmErrorCode::InternalError
				}
			};
			Response::Error(qos_proto::NsmErrorResponse {
				code: proto_code as i32,
			})
		}
	};

	qos_proto::NsmResponse { response: Some(inner) }
}

/// Extension trait for Approval verification.
pub trait ApprovalExt {
	/// Verify that the approval is a valid signature for the given `msg`.
	fn verify(&self, msg: &[u8]) -> Result<(), ProtocolError>;
}

impl ApprovalExt for Approval {
	fn verify(&self, msg: &[u8]) -> Result<(), ProtocolError> {
		let member =
			self.member.as_ref().ok_or(ProtocolError::MissingApprovalMember)?;
		let pub_key = P256Public::from_bytes(&member.pub_key)?;

		if pub_key.verify(msg, &self.signature).is_ok() {
			Ok(())
		} else {
			Err(ProtocolError::CouldNotVerifyApproval)
		}
	}
}

/// Extension trait for ManifestEnvelope validation.
pub trait ManifestEnvelopeExt {
	/// Check if the encapsulated manifest has K valid approvals from the
	/// manifest approval set.
	fn check_approvals(&self) -> Result<(), ProtocolError>;
}

impl ManifestEnvelopeExt for ManifestEnvelope {
	fn check_approvals(&self) -> Result<(), ProtocolError> {
		let manifest =
			self.manifest.as_ref().ok_or(ProtocolError::MissingManifest)?;
		let manifest_set = manifest
			.manifest_set
			.as_ref()
			.ok_or(ProtocolError::MissingManifestSet)?;

		let mut uniq_members = HashSet::new();
		for approval in &self.manifest_set_approvals {
			let member = approval
				.member
				.as_ref()
				.ok_or(ProtocolError::MissingApprovalMember)?;
			let member_pub_key = P256Public::from_bytes(&member.pub_key)?;

			// Ensure that this is a valid signature from the member
			let is_valid_signature = member_pub_key
				.verify(&manifest.proto_hash(), &approval.signature)
				.is_ok();
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}

			// Ensure that this member belongs to the manifest set
			if !manifest_set.members.contains(member) {
				return Err(ProtocolError::NotManifestSetMember);
			}

			// Ensure that the member only has 1 approval. Note that we don't
			// include the signature in this check because the signature is
			// malleable. i.e. there could be two different signatures per
			// member.
			if !uniq_members.insert(member.proto_hash()) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}

		// Ensure that there are at least threshold unique members who approved
		if uniq_members.len() < manifest_set.threshold as usize {
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
	// 1. Check signatures over the manifest envelope.
	manifest_envelope.check_approvals()?;
	if !manifest_envelope.share_set_approvals.is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}

	let manifest =
		manifest_envelope.manifest.as_ref().ok_or(ProtocolError::MissingManifest)?;
	let pivot_config =
		manifest.pivot.as_ref().ok_or(ProtocolError::MissingPivotConfig)?;

	if sha_256(pivot) != pivot_config.hash.as_slice() {
		return Err(ProtocolError::InvalidPivotHash);
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
		manifest.proto_hash().to_vec(),
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
			namespace: Some(Namespace {
				nonce: 420,
				name: "vape lord".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			}),
			enclave: Some(NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			}),
			pivot: Some(PivotConfig {
				hash: sha_256(&pivot).to_vec(),
				restart: RestartPolicy::Always as i32,
				args: vec![],
			}),
			manifest_set: Some(ManifestSet {
				threshold: 2,
				members: quorum_members,
			}),
			share_set: Some(ShareSet { threshold: 2, members: vec![] }),
			patch_set: Some(PatchSet::default()),
			client_timeout_ms: None,
			pool_size: None,
		};

		(manifest, member_with_keys, pivot)
	}

	#[test]
	fn manifest_hash() {
		let (manifest, _members, _pivot) = get_manifest();

		let hashes: Vec<_> = (0..10).map(|_| manifest.proto_hash()).collect();
		let is_valid = (1..10).all(|i| hashes[i] == hashes[0]);
		assert!(is_valid);
	}

	#[test]
	fn boot_standard_accepts_approved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.proto_hash();
			let approvals = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: Some(member),
				})
				.collect();

			ManifestEnvelope {
				manifest: Some(manifest),
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
		let threshold =
			manifest.manifest_set.as_ref().unwrap().threshold as usize;

		let manifest_envelope = {
			let manifest_hash = manifest.proto_hash();
			let approvals = members[0usize..threshold - 1]
				.iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: Some(member.clone()),
				})
				.collect();

			ManifestEnvelope {
				manifest: Some(manifest),
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
					member: Some(member),
				})
				.collect();

			ManifestEnvelope {
				manifest: Some(manifest),
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
			let manifest_hash = manifest.proto_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: Some(member),
				})
				.collect();

			ManifestEnvelope {
				manifest: Some(manifest),
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
			let manifest_hash = manifest.proto_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: Some(member),
				})
				.collect();

			// Change a member so that they are not recognized as part of the
			// manifest set.
			let approval = approvals.get_mut(0).unwrap();
			let pair = P256Pair::generate().unwrap();
			let mut member = approval.member.take().unwrap();
			member.pub_key = pair.public_key().to_bytes();
			approval.member = Some(member);
			approval.signature = pair.sign(&manifest.proto_hash()).unwrap();

			ManifestEnvelope {
				manifest: Some(manifest),
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
			let manifest_hash = manifest.proto_hash();
			// Just make 1 approval
			let mut approvals: Vec<_> = members[..1]
				.iter()
				.cloned()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: Some(member),
				})
				.collect();

			// Duplicate the approval and add it
			let duplicate_approval = approvals[0].clone();
			approvals.push(duplicate_approval);

			ManifestEnvelope {
				manifest: Some(manifest),
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![],
			}
		};

		let err = manifest_envelope.check_approvals().unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateApproval);
	}
}
