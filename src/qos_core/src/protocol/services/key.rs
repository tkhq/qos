//! The services involved in the key forwarding flow.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use borsh::{BorshDeserialize, BorshSerialize};
use qos_nsm::{
	nitro::{attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM},
	types::NsmResponse,
};
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	services::boot::{put_manifest_and_pivot, ManifestEnvelope},
	ProtocolError, ProtocolState,
};

/// An encrypted quorum key along with a signature over the encrypted payload
/// from the sender.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct EncryptedQuorumKey {
	/// The encrypted payload: a quorum key
	pub encrypted_quorum_key: Vec<u8>,
	/// Signature over the encrypted quorum key
	pub signature: Vec<u8>,
}

pub(in crate::protocol) fn inject_key(
	state: &mut ProtocolState,
	EncryptedQuorumKey { encrypted_quorum_key, signature }: EncryptedQuorumKey,
) -> Result<(), ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;

	// verify signature
	let quorum_public = P256Public::from_bytes(
		&manifest_envelope.manifest.namespace.quorum_key,
	)?;
	quorum_public
		.verify(&encrypted_quorum_key, &signature)
		.map_err(|_| ProtocolError::InvalidEncryptedQuorumKeySignature)?;

	// get the decrypted quorum pair
	let quorum_master_seed = {
		let ephemeral_pair = state.handles.get_ephemeral_key()?;
		let bytes = ephemeral_pair.decrypt(&encrypted_quorum_key)?;
		bytes
			.try_into()
			.map_err(|_| ProtocolError::EncryptedQuorumKeyInvalidLen)?
	};
	let decrypted_quorum_pair = P256Pair::from_master_seed(&quorum_master_seed)
		.map_err(|_| ProtocolError::InvalidQuorumSecret)?;
	if decrypted_quorum_pair.public_key() != quorum_public {
		return Err(ProtocolError::WrongQuorumKey);
	}
	state.handles.put_quorum_key(&decrypted_quorum_pair)?;
	Ok(())
}

pub(in crate::protocol) fn boot_key_forward(
	state: &mut ProtocolState,
	manifest_envelope: &ManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	let nsm_response = put_manifest_and_pivot(state, manifest_envelope, pivot)?;
	Ok(nsm_response)
}

pub(in crate::protocol) fn export_key(
	state: &mut ProtocolState,
	new_manifest_envelope: &ManifestEnvelope,
	cose_sign1_attestation_document: &[u8],
) -> Result<EncryptedQuorumKey, ProtocolError> {
	let attestation_doc = verify_and_extract_attestation_doc_from_der(
		cose_sign1_attestation_document,
		&*state.attestor,
	)?;

	export_key_internal(state, new_manifest_envelope, &attestation_doc)
}

// Primary logic of `export_key` pulled out so it can be unit tested.
fn export_key_internal(
	state: &mut ProtocolState,
	new_manifest_envelope: &ManifestEnvelope,
	attestation_doc: &AttestationDoc,
) -> Result<EncryptedQuorumKey, ProtocolError> {
	let old_manifest_envelope = state.handles.get_manifest_envelope()?;
	validate_manifest(
		new_manifest_envelope,
		&old_manifest_envelope,
		attestation_doc,
	)?;

	let eph_key = {
		#[cfg(not(feature = "mock"))]
		{
			let eph_key_bytes = attestation_doc
				.public_key
				.as_ref()
				.ok_or(ProtocolError::MissingEphemeralKey)?;
			P256Public::from_bytes(eph_key_bytes)
				.map_err(|_| ProtocolError::InvalidEphemeralKey)?
		}
		#[cfg(feature = "mock")]
		{
			// For testing, the old enclave and new enclave will need to share
			// an ephemeral key for this to work
			state.handles.get_ephemeral_key()?.public_key()
		}
	};

	let quorum_key = state.handles.get_quorum_key()?;
	let encrypted_quorum_key = eph_key.encrypt(quorum_key.to_master_seed())?;
	let signature = quorum_key.sign(&encrypted_quorum_key)?;

	Ok(EncryptedQuorumKey { encrypted_quorum_key, signature })
}

/// Manifest validation logic. Extracted to make unit testing easier.
fn validate_manifest(
	new_manifest_envelope: &ManifestEnvelope,
	old_manifest_envelope: &ManifestEnvelope,
	_attestation_doc: &AttestationDoc,
) -> Result<(), ProtocolError> {
	new_manifest_envelope.check_approvals()?;

	if !new_manifest_envelope.share_set_approvals.is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}

	if old_manifest_envelope.manifest.namespace.quorum_key
		!= new_manifest_envelope.manifest.namespace.quorum_key
	{
		return Err(ProtocolError::DifferentQuorumKey);
	}

	{
		let mut new_manifest = new_manifest_envelope.manifest.clone();
		let mut old_manifest = old_manifest_envelope.manifest.clone();
		new_manifest.manifest_set.members.sort();
		old_manifest.manifest_set.members.sort();
		if old_manifest.manifest_set != new_manifest.manifest_set {
			return Err(ProtocolError::DifferentManifestSet);
		}
	}

	if old_manifest_envelope.manifest.namespace.name
		!= new_manifest_envelope.manifest.namespace.name
	{
		return Err(ProtocolError::DifferentNamespaceName);
	}

	if old_manifest_envelope.manifest.namespace.nonce
		> new_manifest_envelope.manifest.namespace.nonce
	{
		return Err(ProtocolError::LowNonce);
	}

	#[cfg(not(feature = "mock"))]
	{
		use crate::protocol::QosHash;
		qos_nsm::nitro::verify_attestation_doc_against_user_input(
			_attestation_doc,
			&new_manifest_envelope.manifest.qos_hash(),
			&new_manifest_envelope.manifest.enclave.pcr0,
			&new_manifest_envelope.manifest.enclave.pcr1,
			&new_manifest_envelope.manifest.enclave.pcr2,
			&new_manifest_envelope.manifest.enclave.pcr3,
		)?;
	}

	if old_manifest_envelope.manifest.enclave.pcr3
		!= new_manifest_envelope.manifest.enclave.pcr3
	{
		return Err(ProtocolError::DifferentPcr3);
	}

	Ok(())
}

fn verify_and_extract_attestation_doc_from_der(
	cose_sign1_der: &[u8],
	nsm: &dyn qos_nsm::NsmProvider,
) -> Result<AttestationDoc, ProtocolError> {
	let current_time_milliseconds = nsm.timestamp_ms()?;
	let current_time_seconds = current_time_milliseconds / 1_000;
	let der_cert = cert_from_pem(AWS_ROOT_CERT_PEM)
		.expect("hardcoded cert is valid. qed.");
	attestation_doc_from_der(cose_sign1_der, &der_cert, current_time_seconds)
		.map_err(Into::into)
}

#[cfg(test)]
mod test {
	use std::{collections::BTreeMap, ops::Deref};

	use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
	use borsh::BorshSerialize;
	use qos_crypto::sha_256;
	use qos_nsm::{mock::MockNsm, types::NsmResponse};
	use qos_p256::P256Pair;
	use qos_test_primitives::PathWrapper;
	use serde_bytes::ByteBuf;

	use super::{boot_key_forward, export_key_internal, validate_manifest};
	use crate::{
		handles::Handles,
		io::SocketAddress,
		protocol::{
			services::{
				boot::{
					Approval, Manifest, ManifestEnvelope, ManifestSet,
					Namespace, NitroConfig, PivotConfig, QuorumMember,
					RestartPolicy, ShareSet,
				},
				key::{inject_key, EncryptedQuorumKey},
			},
			ProtocolError, ProtocolPhase, ProtocolState, QosHash,
		},
	};

	struct TestArgs {
		manifest_envelope: ManifestEnvelope,
		members_with_keys: Vec<(P256Pair, QuorumMember)>,
		att_doc: AttestationDoc,
		eph_pair: P256Pair,
		quorum_pair: P256Pair,
		pivot: Vec<u8>,
	}

	fn get_test_args() -> TestArgs {
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

		let members_with_keys = vec![
			(member1_pair, quorum_members.get(0).unwrap().clone()),
			(member2_pair, quorum_members.get(1).unwrap().clone()),
			(member3_pair, quorum_members.get(2).unwrap().clone()),
		];

		let pcr0 = vec![4; 32];
		let pcr1 = vec![3; 32];
		let pcr2 = vec![2; 32];
		let pcr3 = vec![1; 32];
		let manifest = Manifest {
			namespace: Namespace {
				nonce: 420,
				name: "mock namespace".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: pcr0.clone(),
				pcr1: pcr1.clone(),
				pcr2: pcr2.clone(),
				pcr3: pcr3.clone(),
				aws_root_certificate: b"mock cert".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			},
			pivot: PivotConfig {
				commit: "mock commit".to_string(),
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
			},
			manifest_set: ManifestSet { threshold: 2, members: quorum_members },
			share_set: ShareSet { threshold: 2, members: vec![] },
		};

		let manifest_set_approvals = (0..2)
			.map(|i| {
				let (pair, member) = &members_with_keys[i];
				Approval {
					signature: pair.sign(&manifest.qos_hash()).unwrap(),
					member: member.clone(),
				}
			})
			.collect();

		let mut pcr_map = BTreeMap::new();
		pcr_map.insert(0, ByteBuf::from(pcr0));
		pcr_map.insert(1, ByteBuf::from(pcr1));
		pcr_map.insert(2, ByteBuf::from(pcr2));
		pcr_map.insert(3, ByteBuf::from(pcr3));

		let eph_pair = P256Pair::generate().unwrap();
		let eph_pub_key = eph_pair.public_key().to_bytes();

		let att_doc = AttestationDoc {
			module_id: String::default(),
			cabundle: Vec::default(),
			pcrs: pcr_map,
			timestamp: u64::default(),
			nonce: None,
			public_key: Some(ByteBuf::from(eph_pub_key)),
			user_data: Some(ByteBuf::from(manifest.qos_hash())),
			digest: Digest::SHA384,
			certificate: ByteBuf::default(),
		};

		let manifest_envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals,
			share_set_approvals: Vec::default(),
		};

		TestArgs {
			manifest_envelope,
			members_with_keys,
			att_doc,
			eph_pair,
			quorum_pair,
			pivot,
		}
	}

	mod boot_key_forward {
		use super::*;

		#[test]
		fn accepts_approved_manifest() {
			let TestArgs { manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file: PathWrapper =
				"/tmp/boot_key_forward_accepts_approved_manifest.pivot".into();
			let ephemeral_file: PathWrapper =
				"/tmp/boot_key_accepts_approved_manifest.eph.secret".into();
			let manifest_file: PathWrapper =
				"/tmp/boot_key_accepts_approved_manifest.manifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"qorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm),
				handles.clone(),
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			let response =
				boot_key_forward(&mut state, &manifest_envelope, &pivot)
					.unwrap();
			match response {
				NsmResponse::Attestation { document } => {
					assert!(!document.is_empty());
				}
				_ => panic!(),
			};

			assert!(handles.pivot_exists());
			assert_eq!(
				handles.get_manifest_envelope().unwrap(),
				manifest_envelope
			);

			handles.get_ephemeral_key().unwrap();
		}

		#[test]
		fn rejects_manifest_if_not_enough_approvals() {
			let TestArgs { mut manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.pivot"
					.into();
			let ephemeral_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.secret"
					.into();
			let manifest_file: PathWrapper = "/tmp/boot_key_rejects_manifest_if_not_enough_approvals.manifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"qorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm),
				handles.clone(),
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			// Remove an approval
			manifest_envelope.manifest_set_approvals.pop().unwrap();
			let err = boot_key_forward(&mut state, &manifest_envelope, &pivot);
			assert_eq!(Err(ProtocolError::NotEnoughApprovals), err,);

			// check that nothing was written
			assert!(!handles.pivot_exists());
			assert!(!handles.manifest_envelope_exists());
			// phase hasn't changed
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}

		#[test]
		fn rejects_manifest_if_wrong_pivot_hash() {
			let TestArgs { manifest_envelope, .. } = get_test_args();

			let pivot_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.pivot"
					.into();
			let ephemeral_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.secret"
					.into();
			let manifest_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.manifest"
					.into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"qorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm),
				handles.clone(),
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			// Use a different pivot then what is referenced in the manifest
			let other_pivot = b"other pivot".to_vec();
			let err =
				boot_key_forward(&mut state, &manifest_envelope, &other_pivot);
			assert_eq!(Err(ProtocolError::InvalidPivotHash), err,);

			// check that nothing was written
			assert!(!handles.pivot_exists());
			assert!(!handles.manifest_envelope_exists());
			// phase hasn't changed
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}

		#[test]
		fn rejects_manifest_with_bad_approval_signature() {
			let TestArgs { mut manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file: PathWrapper = "/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.pivot".into();
			let ephemeral_file: PathWrapper = "/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.secret".into();
			let manifest_file: PathWrapper = "/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.manifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"quorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm),
				handles.clone(),
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			// Change the signature to something invalid
			manifest_envelope.manifest_set_approvals[0].signature = vec![1; 32];
			let bad_approval =
				manifest_envelope.manifest_set_approvals[0].clone();

			let err = boot_key_forward(&mut state, &manifest_envelope, &pivot);
			assert_eq!(
				Err(ProtocolError::InvalidManifestApproval(bad_approval)),
				err,
			);

			// check that nothing was written
			assert!(!handles.pivot_exists());
			assert!(!handles.manifest_envelope_exists());
			// phase hasn't changed
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}

		#[test]
		fn rejects_manifest_with_approval_from_non_member() {
			let TestArgs { mut manifest_envelope, pivot, .. } = get_test_args();

			let non_member_pair = P256Pair::generate().unwrap();
			let non_member = QuorumMember {
				alias: "member1".to_string(),
				pub_key: non_member_pair.public_key().to_bytes(),
			};
			let non_member_approval = Approval {
				signature: non_member_pair
					.sign(&manifest_envelope.manifest.qos_hash())
					.unwrap(),
				member: non_member,
			};

			let pivot_file: PathWrapper = "/tmp/boot_key_reject_manifest_with_approval_from_non_memberpivot".into();
			let ephemeral_file: PathWrapper = "/tmp/boot_key_reject_manifest_with_approval_from_non_membersecret".into();
			let manifest_file: PathWrapper = "/tmp/boot_key_reject_manifest_with_approval_from_non_membermanifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"quorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm),
				handles.clone(),
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			// Add an approval from a random key
			manifest_envelope.manifest_set_approvals.push(non_member_approval);

			let err = boot_key_forward(&mut state, &manifest_envelope, &pivot);
			assert_eq!(Err(ProtocolError::NotManifestSetMember), err,);

			// check that nothing was written
			assert!(!handles.pivot_exists());
			assert!(!handles.manifest_envelope_exists());
			// phase hasn't changed
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}
	}

	mod validate_manifest {
		use super::*;
		#[test]
		fn accepts_matching_manifests() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			assert!(validate_manifest(
				&manifest_envelope,
				&manifest_envelope,
				&att_doc
			)
			.is_ok());
		}

		#[test]
		fn accepts_manifest_with_greater_nonce() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(validate_manifest(
				&manifest_envelope,
				&old_manifest_envelope,
				&att_doc
			)
			.is_ok());
		}

		#[test]
		fn rejects_manifest_with_lower_nonce() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.nonce += 1;

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::LowNonce)
			);
		}

		#[test]
		fn rejects_manifest_with_different_quorum_key() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			let different_quorum_key =
				P256Pair::generate().unwrap().public_key().to_bytes();
			old_manifest_envelope.manifest.namespace.quorum_key =
				different_quorum_key;

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentQuorumKey)
			);
		}

		#[test]
		fn rejects_manifest_with_different_manifest_set() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.manifest_set.members.pop();

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentManifestSet)
			);

			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.manifest_set.threshold = 1;
			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentManifestSet)
			);
		}

		#[test]
		fn accepts_manifest_with_different_ordered_manifest_set_members() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			let last_member =
				old_manifest_envelope.manifest.manifest_set.members.remove(2);
			old_manifest_envelope
				.manifest
				.manifest_set
				.members
				.insert(0, last_member);

			assert!(validate_manifest(
				&manifest_envelope,
				&old_manifest_envelope,
				&att_doc
			)
			.is_ok());
		}

		#[test]
		fn rejects_manifest_with_different_namespace_name() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.name =
				"other namespace".to_string();

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentNamespaceName),
			);
		}

		#[test]
		fn reject_manifest_with_different_pcr3() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.enclave.pcr3 = vec![128; 32];

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentPcr3),
			);
		}

		#[test]
		fn errors_with_two_few_manifest_approvals() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();

			new_manifest_envelope.manifest_set_approvals.pop().unwrap();
			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::NotEnoughApprovals)
			);
		}

		#[test]
		fn rejects_manifest_with_bad_approval_signature() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();

			new_manifest_envelope.manifest_set_approvals[0].signature =
				vec![1; 32];
			let bad_approval =
				new_manifest_envelope.manifest_set_approvals[0].clone();

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::InvalidManifestApproval(bad_approval))
			);
		}

		#[test]
		fn rejects_manifest_with_approval_from_non_member() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			let non_member_pair = P256Pair::generate().unwrap();

			let non_member = QuorumMember {
				alias: "member1".to_string(),
				pub_key: non_member_pair.public_key().to_bytes(),
			};
			let non_member_approval = Approval {
				signature: non_member_pair
					.sign(&manifest_envelope.manifest.qos_hash())
					.unwrap(),
				member: non_member,
			};
			// Add approval from
			new_manifest_envelope
				.manifest_set_approvals
				.push(non_member_approval);

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::NotManifestSetMember)
			);
		}
	}

	#[cfg(not(feature = "mock"))]
	mod validate_manifest_mock_disabled_tests {
		use super::*;
		#[test]
		fn errors_if_pcr0_does_match_attestation_doc() {
			let TestArgs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			new_manifest_envelope.manifest.enclave.pcr0 = vec![128; 32];

			let new_manifest_hash = new_manifest_envelope.manifest.qos_hash();
			att_doc.user_data = Some(ByteBuf::from(new_manifest_hash));

			let manifest_set_approvals = (0..2)
				.map(|i| {
					let (pair, member) = &members_with_keys[i];
					Approval {
						signature: pair.sign(&new_manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();
			new_manifest_envelope.manifest_set_approvals =
				manifest_set_approvals;

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::QosAttestError("DifferentPcr0".to_string()))
			);
		}

		#[test]
		fn errors_if_pcr1_does_match_attestation_doc() {
			let TestArgs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			new_manifest_envelope.manifest.enclave.pcr1 = vec![128; 32];

			let new_manifest_hash = new_manifest_envelope.manifest.qos_hash();
			att_doc.user_data = Some(ByteBuf::from(new_manifest_hash));

			let manifest_set_approvals = (0..2)
				.map(|i| {
					let (pair, member) = &members_with_keys[i];
					Approval {
						signature: pair.sign(&new_manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();
			new_manifest_envelope.manifest_set_approvals =
				manifest_set_approvals;

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::QosAttestError("DifferentPcr1".to_string()))
			);
		}

		#[test]
		fn errors_if_pcr2_does_match_attesation_doc() {
			let TestArgs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			new_manifest_envelope.manifest.enclave.pcr2 = vec![128; 32];

			let new_manifest_hash = new_manifest_envelope.manifest.qos_hash();
			att_doc.user_data = Some(ByteBuf::from(new_manifest_hash));

			let manifest_set_approvals = (0..2)
				.map(|i| {
					let (pair, member) = &members_with_keys[i];
					Approval {
						signature: pair.sign(&new_manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();
			new_manifest_envelope.manifest_set_approvals =
				manifest_set_approvals;

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::QosAttestError("DifferentPcr2".to_string()))
			);
		}

		#[test]
		fn errors_if_pcr3_does_match_attestation_doc() {
			let TestArgs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			new_manifest_envelope.manifest.enclave.pcr3 = vec![128; 32];

			// Also update the old manifest to have the same pcr3 so the issue
			// is isolated to mismatching the attestation doc.
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.enclave.pcr3 = vec![128; 32];

			let new_manifest_hash = new_manifest_envelope.manifest.qos_hash();
			att_doc.user_data = Some(ByteBuf::from(new_manifest_hash));

			let manifest_set_approvals = (0..2)
				.map(|i| {
					let (pair, member) = &members_with_keys[i];
					Approval {
						signature: pair.sign(&new_manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();
			new_manifest_envelope.manifest_set_approvals =
				manifest_set_approvals;

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::QosAttestError("DifferentPcr3".to_string()))
			);
		}

		#[test]
		fn errors_if_manifest_hash_does_not_match_attestation_doc() {
			let TestArgs {
				manifest_envelope, att_doc, members_with_keys, ..
			} = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();
			new_manifest_envelope.manifest.namespace.nonce += 1;

			let manifest_set_approvals = (0..2)
				.map(|i| {
					let (pair, member) = &members_with_keys[i];
					Approval {
						signature: pair
							.sign(&new_manifest_envelope.manifest.qos_hash())
							.unwrap(),
						member: member.clone(),
					}
				})
				.collect();
			new_manifest_envelope.manifest_set_approvals =
				manifest_set_approvals;

			// Don't update the manifest hash in the attestation doc

			assert_eq!(
				validate_manifest(
					&new_manifest_envelope,
					&manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::QosAttestError(
					"DifferentUserData".to_string()
				))
			);
		}
	}
	mod export_key_inner {
		use super::*;
		use crate::protocol::services::key::EncryptedQuorumKey;

		#[test]
		fn works() {
			let TestArgs {
				manifest_envelope,
				att_doc,
				eph_pair,
				quorum_pair,
				..
			} = get_test_args();

			let ephemeral_file: PathWrapper =
				"export_key_inner_works.eph.secret".into();
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();

			let manifest_file: PathWrapper =
				"export_key_inner_works.manifest".into();

			let quorum_file: PathWrapper =
				"export_key_inner_works.quorum.secret".into();
			quorum_pair.to_hex_file(&*quorum_file).unwrap();

			std::fs::write(
				&*manifest_file,
				manifest_envelope.try_to_vec().unwrap(),
			)
			.unwrap();
			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);

			let mut protocol_state = ProtocolState::new(
				Box::new(MockNsm),
				handles,
				SocketAddress::new_unix("./never.sock"),
				None,
			);
			let EncryptedQuorumKey { encrypted_quorum_key, signature } =
				export_key_internal(
					&mut protocol_state,
					&manifest_envelope,
					&att_doc,
				)
				.unwrap();

			// quorum key signature over payload is valid
			assert!(quorum_pair
				.public_key()
				.verify(&encrypted_quorum_key, &signature)
				.is_ok());

			let decrypted_quorum_secret =
				eph_pair.decrypt(&encrypted_quorum_key).unwrap();
			let reconstructed_quorum_pair = P256Pair::from_master_seed(
				&decrypted_quorum_secret.try_into().unwrap(),
			)
			.unwrap();
			assert!(quorum_pair == reconstructed_quorum_pair);
		}
	}

	mod inject_key {

		use super::*;

		#[test]
		fn works() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file: PathWrapper =
				"inject_key_works.eph.secret".into();
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file: PathWrapper = "inject_key_works.manifest".into();
			let quorum_file: PathWrapper =
				"inject_key_works.quorum.secret".into();
			std::fs::write(
				&*manifest_file,
				manifest_envelope.try_to_vec().unwrap(),
			)
			.unwrap();

			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(quorum_pair.to_master_seed())
				.unwrap();
			let signature = quorum_pair.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state = ProtocolState::new(
				Box::new(MockNsm),
				handles,
				SocketAddress::new_unix("./never.sock"),
				None,
			);
			protocol_state
				.transition(ProtocolPhase::WaitingForForwardedKey)
				.unwrap();

			assert_eq!(
				inject_key(
					&mut protocol_state,
					EncryptedQuorumKey { encrypted_quorum_key, signature }
				),
				Ok(())
			);

			// writes the quorum key
			assert!(protocol_state.handles.quorum_key_exists());
		}

		#[test]
		fn rejects_wrong_encrypted_key() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file: PathWrapper =
				"inject_rejects_bad_signature.eph.secret".into();
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file: PathWrapper =
				"inject_rejects_bad_signature.manifest".into();
			let quorum_file: PathWrapper =
				"inject_rejects_bad_signature.quorum.secret".into();
			std::fs::write(
				&*manifest_file,
				manifest_envelope.try_to_vec().unwrap(),
			)
			.unwrap();

			let wrong_key = P256Pair::generate().unwrap();
			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(wrong_key.to_master_seed())
				.unwrap();
			let signature = quorum_pair.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state = ProtocolState::new(
				Box::new(MockNsm),
				handles,
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			assert_eq!(
				inject_key(
					&mut protocol_state,
					EncryptedQuorumKey { encrypted_quorum_key, signature }
				),
				Err(ProtocolError::WrongQuorumKey)
			);

			// does not write the quorum key
			assert!(!protocol_state.handles.quorum_key_exists());
			// does not change phase
			assert_eq!(
				protocol_state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}

		#[test]
		fn rejects_bad_signature() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file: PathWrapper =
				"inject_key_rejects_wrong_quorum_key.eph.secret".into();
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file: PathWrapper =
				"inject_key_rejects_wrong_quorum_key.manifest".into();
			let quorum_file: PathWrapper =
				"inject_key_rejects_wrong_quorum_key.quorum.secret".into();
			std::fs::write(
				&*manifest_file,
				manifest_envelope.try_to_vec().unwrap(),
			)
			.unwrap();

			let wrong_key = P256Pair::generate().unwrap();
			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(quorum_pair.to_master_seed())
				.unwrap();
			let signature = wrong_key.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state = ProtocolState::new(
				Box::new(MockNsm),
				handles,
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			assert_eq!(
				inject_key(
					&mut protocol_state,
					EncryptedQuorumKey { encrypted_quorum_key, signature }
				),
				Err(ProtocolError::InvalidEncryptedQuorumKeySignature)
			);

			// does not write the quorum key
			assert!(!protocol_state.handles.quorum_key_exists());
			// does not change phase
			assert_eq!(
				protocol_state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}

		#[test]
		fn rejects_invalid_quorum_key() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file: PathWrapper =
				"inject_key_rejects_invalid_quorum_key.eph.secret".into();
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file: PathWrapper =
				"inject_key_rejects_invalid_quorum_key.manifest".into();
			let quorum_file: PathWrapper =
				"inject_key_rejects_invalid_quorum_key.quorum.secret".into();
			std::fs::write(
				&*manifest_file,
				manifest_envelope.try_to_vec().unwrap(),
			)
			.unwrap();

			let mut invalid_master_seed = quorum_pair.to_master_seed().to_vec();
			invalid_master_seed.remove(0);
			let invalid_encrypted_quorum_key =
				eph_pair.public_key().encrypt(&invalid_master_seed).unwrap();
			let signature =
				quorum_pair.sign(&invalid_encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state = ProtocolState::new(
				Box::new(MockNsm),
				handles,
				SocketAddress::new_unix("./never.sock"),
				None,
			);

			assert_eq!(
				inject_key(
					&mut protocol_state,
					EncryptedQuorumKey {
						encrypted_quorum_key: invalid_encrypted_quorum_key,
						signature
					}
				),
				Err(ProtocolError::EncryptedQuorumKeyInvalidLen)
			);

			// does not write the quorum key
			assert!(!protocol_state.handles.quorum_key_exists());
			// does not change phase
			assert_eq!(
				protocol_state.get_phase(),
				ProtocolPhase::WaitingForBootInstruction
			);
		}
	}
}
