//! The services involved in the key forwarding flow.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use qos_attest::{
	current_time,
	nitro::{attestation_doc_from_der, AWS_ROOT_CERT_PEM},
};
use qos_nsm::types::NsmResponse;
use qos_p256::P256Public;

use crate::protocol::{
	services::boot::{put_manifest_and_pivot, ManifestEnvelope},
	ProtocolError, ProtocolPhase, ProtocolState, QosHash,
};

pub(in crate::protocol) fn boot_key_forward(
	state: &mut ProtocolState,
	manifest_envelope: &ManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	let nsm_response = put_manifest_and_pivot(state, manifest_envelope, pivot)?;

	state.phase = ProtocolPhase::WaitingForForwardedKey;

	Ok(nsm_response)
}

pub(in crate::protocol) fn request_key(
	state: &mut ProtocolState,
	new_manifest_envelope: &ManifestEnvelope,
	cose_sign1_attestation_document: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
	// 1) Check the basic validity of the attestation doc (cert chain etc).
	// Ensures that the attestation document is actually from an AWS controlled
	// NSM module and the document's timestamp was recent.
	let attestation_doc = verify_and_extract_attestation_doc_from_der(
		cose_sign1_attestation_document,
		&*state.attestor,
	)?;

	request_key_internal(state, new_manifest_envelope, &attestation_doc)
}

// Primary of `request_key` pulled out to make testing easier.
fn request_key_internal(
	state: &mut ProtocolState,
	new_manifest_envelope: &ManifestEnvelope,
	attestation_doc: &AttestationDoc,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
	let old_manifest_envelope = state.handles.get_manifest_envelope()?;
	validate_manifest(
		new_manifest_envelope,
		&old_manifest_envelope,
		attestation_doc,
	)?;

	// TODO: Add pcr3 allow list to manifest. We don't need to use it yet, but
	// better to add a breaking change to the manifest shape now. 1) Check that
	// the PCR3 allowlist in the New Manifest is a sub set of the PCR3 allowlist
	// in the Local Manifest. This is not strictly necessary, but since adding a
	// value for PCR3 could lead to a non-operator controlled entity gaining
	// access to a Quorum Key, we want to force human intervention (with
	// standard boot) to add a new value to the allowlist.

	let eph_key = {
		let eph_key_bytes = attestation_doc
			.public_key
			.as_ref()
			.ok_or(ProtocolError::MissingEphemeralKey)?;
		P256Public::from_bytes(eph_key_bytes)
			.map_err(|_| ProtocolError::InvalidEphemeralKey)?
	};
	let quorum_key = state.handles.get_quorum_key()?;
	let encrypted_payload = eph_key.encrypt(quorum_key.to_master_seed())?;
	let signature = quorum_key.sign(&encrypted_payload)?;

	Ok((encrypted_payload, signature))
}

/// Manifest validation logic. Extracted to make unit testing easier.
fn validate_manifest(
	new_manifest_envelope: &ManifestEnvelope,
	old_manifest_envelope: &ManifestEnvelope,
	attestation_doc: &AttestationDoc,
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

	qos_attest::nitro::verify_attestation_doc_against_user_input(
		attestation_doc,
		&new_manifest_envelope.manifest.qos_hash(),
		&new_manifest_envelope.manifest.enclave.pcr0,
		&new_manifest_envelope.manifest.enclave.pcr1,
		&new_manifest_envelope.manifest.enclave.pcr2,
		&new_manifest_envelope.manifest.enclave.pcr3,
	)?;

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
	let current_time = current_time(nsm)?;
	attestation_doc_from_der(cose_sign1_der, AWS_ROOT_CERT_PEM, current_time)
		.map_err(Into::into)
}

#[cfg(test)]
mod test {
	use std::collections::BTreeMap;

	use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
	use qos_crypto::sha_256;
	use qos_p256::P256Pair;
	use serde_bytes::ByteBuf;

	use super::validate_manifest;
	use crate::protocol::{
		services::boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, Namespace,
			NitroConfig, PivotConfig, QuorumMember, RestartPolicy, ShareSet,
		},
		QosHash,
	};

	struct TestInputs {
		manifest_envelope: ManifestEnvelope,
		members_with_keys: Vec<(P256Pair, QuorumMember)>,
		att_doc: AttestationDoc,
	}

	fn get_manifest() -> TestInputs {
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

		let eph_key = P256Pair::generate().unwrap();
		let eph_pub_key = eph_key.public_key().to_bytes();

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

		TestInputs { manifest_envelope, members_with_keys, att_doc }
	}

	mod validate_manifest {
		use super::*;
		use crate::protocol::ProtocolError;
		#[test]
		fn accepts_matching_manifests() {
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
			assert!(validate_manifest(
				&manifest_envelope,
				&manifest_envelope,
				&att_doc
			)
			.is_ok());
		}

		#[test]
		fn accepts_manifest_with_greater_nonce() {
			let TestInputs {
				manifest_envelope,
				att_doc,
				members_with_keys: _,
				..
			} = get_manifest();
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
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
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
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
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
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
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
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
			let mut old_manifest_envelope = manifest_envelope.clone();
			let last_member = old_manifest_envelope
				.manifest
				.manifest_set
				.members
				.pop()
				.unwrap();
			old_manifest_envelope
				.manifest
				.manifest_set
				.members
				.push(last_member);

			assert!(validate_manifest(
				&manifest_envelope,
				&old_manifest_envelope,
				&att_doc
			)
			.is_ok());
		}

		#[test]
		fn rejects_manifest_with_different_namespace_name() {
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
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
			let TestInputs { manifest_envelope, att_doc, .. } = get_manifest();
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
		fn errors_if_manifest_hash_does_not_match_attestation_doc() {
			let TestInputs {
				manifest_envelope,
				att_doc,
				members_with_keys,
				..
			} = get_manifest();
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

		#[test]
		fn errors_if_pcr0_does_match_attesation_doc() {
			let TestInputs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_manifest();
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
		fn errors_if_pcr1_does_match_attesation_doc() {
			let TestInputs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_manifest();
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
			let TestInputs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_manifest();
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
		fn errors_if_pcr3_does_match_attesation_doc() {
			let TestInputs {
				manifest_envelope,
				mut att_doc,
				members_with_keys,
				..
			} = get_manifest();
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
		fn errors_with_two_few_manifest_approvals() {
			let TestInputs {
				manifest_envelope,
				att_doc,
				members_with_keys,
				..
			} = get_manifest();
			let mut new_manifest_envelope = manifest_envelope.clone();

			let manifest_set_approvals = (0..1)
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
				Err(ProtocolError::NotEnoughApprovals)
			);
		}

		#[test]
		fn errors_if_any_share_set_approvals() {}
	}

	mod request_key_inner {
		#[test]
		fn works() {

			// signature is valid
			// encrypts to ephemeral key
		}

		#[test]
		fn errors_with_old_attestation_doc() {}
	}
}
