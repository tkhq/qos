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
	ProtocolError, ProtocolState, QosHash,
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

	// 1. Verify the signature over the `encrypted_quorum_key` against the
	// Quorum Key specified in the New Manifest.
	let quorum_public = P256Public::from_bytes(
		&manifest_envelope.manifest.namespace.quorum_key,
	)?;
	quorum_public
		.verify(&encrypted_quorum_key, &signature)
		.map_err(|_| ProtocolError::InvalidEncryptedQuorumKeySignature)?;

	// 2. Decrypt the encrypted Quorum Key in the request with the Ephemeral
	// Key.
	let quorum_master_seed = {
		let ephemeral_pair = state.handles.get_ephemeral_key()?;
		let bytes = ephemeral_pair.decrypt(&encrypted_quorum_key)?;
		bytes
			.try_into()
			.map_err(|_| ProtocolError::EncryptedQuorumKeyInvalidLen)?
	};

	// 3. Check that the decrypted Quorum Key public key matches the one
	// specified in the New Manifest.
	let decrypted_quorum_pair = P256Pair::from_master_seed(&quorum_master_seed)
		.map_err(|_| ProtocolError::InvalidQuorumSecret)?;
	if decrypted_quorum_pair.public_key() != quorum_public {
		return Err(ProtocolError::WrongQuorumKey);
	}

	// 4. Rotate the ephemeral key so it's safe for apps to use it independently
	// of boot-related operations, which use the pre-boot ephemeral key as
	// an encryption target (key-forward boot encrypts the quorum key to it)
	let new_ephemeral_key = P256Pair::generate()?;
	state.handles.rotate_ephemeral_key(&new_ephemeral_key)?;

	// 5. Write the Quorum Key to the file system, at which point New Node will
	// automatically pivot to running the Pivot App.
	// (see `src/qos_core/src/reaper.rs`: we loop until the quorum key file exists)
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
	// 1. Check the basic validity of the attestation doc (cert chain etc).
	// Ensures that the attestation document is actually from an AWS controlled
	// NSM module and the document's timestamp was recent.
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
	// steps 2 through 9
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
	// 10. Return the Quorum Key encrypted to the New Node's Ephemeral Key
	// extracted from the attestation document and a signature over the
	// encrypted payload. The Original Node uses its Quorum Key to create the
	// signature.
	let encrypted_quorum_key = eph_key.encrypt(quorum_key.to_master_seed())?;
	let signature = quorum_key.sign(&encrypted_quorum_key)?;

	Ok(EncryptedQuorumKey { encrypted_quorum_key, signature })
}

/// Manifest validation logic. Extracted to make unit testing easier.
fn validate_manifest(
	new_manifest_envelope: &ManifestEnvelope,
	old_manifest_envelope: &ManifestEnvelope,
	#[allow(unused_variables)]
	attestation_doc: &AttestationDoc,
) -> Result<(), ProtocolError> {
	// 2. Check the signatures over the New Manifest. Ensures that K Manifest
	// Set Members approved the New Manifest.
	new_manifest_envelope.check_approvals()?;

	if !new_manifest_envelope.share_set_approvals.is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}

	// 3. Check that the Quorum Key of the Local Manifest matches the Quorum Key
	// of the New Manifest. This ensures the request is for the correct Quorum
	// Key.
	if old_manifest_envelope.manifest.namespace.quorum_key
		!= new_manifest_envelope.manifest.namespace.quorum_key
	{
		return Err(ProtocolError::DifferentQuorumKey);
	}

	// 4. Check that the Manifest Set of the New Manifest matches the Manifest
	// Set of the Local Manifest. Ensures that the signatures are from a trusted
	// Manifest Set. Note that there is still a vulnerability here if we have
	// try to retire a Manifest Set because a critical threshold of it was
	// compromised - that malicious Manifest Set could boot off of an Original
	// Node - thus it's important to retire all Original Nodes ASAP that use
	// compromised Manifest Sets.
	{
		let mut new_manifest = new_manifest_envelope.manifest.clone();
		let mut old_manifest = old_manifest_envelope.manifest.clone();
		new_manifest.manifest_set.members.sort();
		old_manifest.manifest_set.members.sort();
		if old_manifest.manifest_set != new_manifest.manifest_set {
			return Err(ProtocolError::DifferentManifestSet);
		}
	}

	// 5. Check that the Namespace of the Local Manifest matches the namespace
	// of the New Manifest. Namespaces are a social construct, but we only want
	// to allow forwarding a Quorum Key to Nodes in the same Namespace to help
	// ensure that the nonce is not abused.
	if old_manifest_envelope.manifest.namespace.name
		!= new_manifest_envelope.manifest.namespace.name
	{
		return Err(ProtocolError::DifferentNamespaceName);
	}

	// 6. Check that the nonce of the New Manifest is greater than or equal to
	// the nonce of the Local Manifest. If they have the same nonce, we check
	// that the Local Manifest has the same hash as an extra measure. Note that
	// while the nonce is verified programmatically in this routine, its
	// maintenance relative to other manifests in the namespace is a social
	// coordination problem and is meant to be solved by the Manifest Set
	// Members approving the manifest. In other words, we rely on the Manifest
	// Set Members to correctly increment the nonce when any change is made to
	// the latest manifest for a namespace.
	if old_manifest_envelope.manifest.namespace.nonce
		> new_manifest_envelope.manifest.namespace.nonce
	{
		return Err(ProtocolError::LowNonce);
	} else if old_manifest_envelope.manifest.namespace.nonce
		== new_manifest_envelope.manifest.namespace.nonce
		&& old_manifest_envelope.manifest.qos_hash()
			!= new_manifest_envelope.manifest.qos_hash()
	{
		return Err(ProtocolError::DifferentManifest);
	}

	// 7. Check that the hash of the new manifest is in the `user_data` field of
	// the attestation doc.
	//
	// 8. Check that PCR0, PCR1, PCR2, and PCR3 in the New
	// Manifest match the PCRs in the attestation document. This ensures the New
	// Manifest was used against a Nitro enclave booted with the intended
	// version of QOS. Note that we assume the values for PCR{0, 1 , 2}
	// correspond to a desired version of QOS because the Manifest Set Members
	// had K approvals.
	#[cfg(not(feature = "mock"))]
	{
		qos_nsm::nitro::verify_attestation_doc_against_user_input(
			attestation_doc,
			&new_manifest_envelope.manifest.qos_hash(),
			&new_manifest_envelope.manifest.enclave.pcr0,
			&new_manifest_envelope.manifest.enclave.pcr1,
			&new_manifest_envelope.manifest.enclave.pcr2,
			&new_manifest_envelope.manifest.enclave.pcr3,
		)?;
	}

	// 9. Check that PCR3 in the New Manifest is in the Local Manifests. PCR3 is
	// the IAM role assigned to the EC2 host of the enclave. An IAM role
	// contains an AWS organization's unique ID. By only using the approved PCR3
	// value we ensure that we only ever send the Quorum Key to an enclave that
	// is controlled by the operator, not an enclave that some malicious entity
	// runs that otherwise configured identically to one of the operator's
	// enclaves.
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
	use qos_crypto::sha_256;
	use qos_nsm::{mock::MockNsm, types::NsmResponse};
	use qos_p256::P256Pair;
	use qos_test_primitives::PathWrapper;
	use serde_bytes::ByteBuf;

	use super::{boot_key_forward, export_key_internal, validate_manifest};
	use crate::{
		handles::Handles,
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
		#[allow(dead_code)]
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
			(member1_pair, quorum_members.first().unwrap().clone()),
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
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
			},
			manifest_set: ManifestSet { threshold: 2, members: quorum_members },
			share_set: ShareSet { threshold: 2, members: vec![] },
			..Default::default()
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
			let mut state =
				ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

			let response =
				boot_key_forward(&mut state, &manifest_envelope, &pivot)
					.unwrap();
			if let NsmResponse::Attestation { document } = response {
				assert!(!document.is_empty());
			} else {
				panic!()
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
			let manifest_file: PathWrapper =
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.manifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"qorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state =
				ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

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
			let mut state =
				ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

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

			let pivot_file: PathWrapper =
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.pivot".into();
			let ephemeral_file: PathWrapper =
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.secret".into();
			let manifest_file: PathWrapper =
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.manifest"
					.into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"quorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state =
				ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

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

			let pivot_file: PathWrapper =
				"/tmp/boot_key_reject_manifest_with_approval_from_non_memberpivot".into();
			let ephemeral_file: PathWrapper =
				"/tmp/boot_key_reject_manifest_with_approval_from_non_membersecret".into();
			let manifest_file: PathWrapper =
				"/tmp/boot_key_reject_manifest_with_approval_from_non_membermanifest".into();

			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				"quorum".to_string(),
				manifest_file.deref().to_string(),
				pivot_file.deref().to_string(),
			);
			let mut state =
				ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

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
		fn rejects_manifest_with_matching_nonce_different_hash() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.enclave.pcr0 = vec![128; 32];

			assert_eq!(
				validate_manifest(
					&manifest_envelope,
					&old_manifest_envelope,
					&att_doc
				),
				Err(ProtocolError::DifferentManifest)
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
		fn does_not_accept_manifest_with_different_manifest_set() {
			let TestArgs { manifest_envelope, att_doc, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.manifest_set.members.pop();
			old_manifest_envelope.manifest.namespace.nonce -= 1;

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

			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(validate_manifest(
				&manifest_envelope,
				&old_manifest_envelope,
				&att_doc
			)
			.is_ok(),);
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
			old_manifest_envelope.manifest.namespace.nonce -= 1;

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
			new_manifest_envelope.manifest.namespace.nonce += 1;
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
				Err(ProtocolError::QosAttestError("DifferentPcr0(\"8080808080808080808080808080808080808080808080808080808080808080\", \"0404040404040404040404040404040404040404040404040404040404040404\")".to_string()))
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
			new_manifest_envelope.manifest.namespace.nonce += 1;
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
			new_manifest_envelope.manifest.namespace.nonce += 1;
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
			new_manifest_envelope.manifest.namespace.nonce += 1;
			new_manifest_envelope.manifest.enclave.pcr3 = vec![128; 32];

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
				borsh::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();
			let handles = Handles::new(
				ephemeral_file.deref().to_string(),
				quorum_file.deref().to_string(),
				manifest_file.deref().to_string(),
				"pivot".to_string(),
			);

			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm), handles, None);
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

		use std::{fs, path::Path};

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
				borsh::to_vec(&manifest_envelope).unwrap(),
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
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm), handles, None);
			protocol_state
				.transition(ProtocolPhase::WaitingForForwardedKey)
				.unwrap();

			let boot_eph_key = fs::read(&*ephemeral_file).unwrap();

			assert_eq!(
				inject_key(
					&mut protocol_state,
					EncryptedQuorumKey { encrypted_quorum_key, signature }
				),
				Ok(())
			);

			// writes the quorum key
			assert!(protocol_state.handles.quorum_key_exists());

			// Make sure the EK is persisted
			assert!(Path::new(&*ephemeral_file).exists());

			// Make sure the EK still exists, and ensure rotation happened post injection
			let new_eph_key = std::fs::read(&*ephemeral_file).unwrap();
			assert_ne!(new_eph_key, boot_eph_key);
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
				borsh::to_vec(&manifest_envelope).unwrap(),
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
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm), handles, None);

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
				borsh::to_vec(&manifest_envelope).unwrap(),
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
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm), handles, None);

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
				borsh::to_vec(&manifest_envelope).unwrap(),
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
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm), handles, None);

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
