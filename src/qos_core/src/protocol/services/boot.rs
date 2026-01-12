//! Standard boot logic and types.

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::P256Pair;

use crate::protocol::{services::attestation, ProtocolError, ProtocolState, QosHash};

pub use crate::protocol::legacy::{
	Approval, Manifest, ManifestEnvelope, ManifestEnvelopeV0, ManifestSet,
	ManifestV0, MemberPubKey, Namespace, NitroConfig, PatchSet, PivotConfig,
	QuorumMember, RestartPolicy, ShareSet,
};

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
	use crate::{handles::Handles, protocol::QosHash};

	fn get_manifest() -> (Manifest, Vec<(qos_p256::P256Pair, QuorumMember)>, Vec<u8>) {
		let quorum_pair = qos_p256::P256Pair::generate().unwrap();
		let member1_pair = qos_p256::P256Pair::generate().unwrap();
		let member2_pair = qos_p256::P256Pair::generate().unwrap();
		let member3_pair = qos_p256::P256Pair::generate().unwrap();

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
			let pair = qos_p256::P256Pair::generate().unwrap();
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
		assert_eq!(manifest.pool_size, None);
		assert_eq!(manifest.client_timeout_ms, None);
	}
}
