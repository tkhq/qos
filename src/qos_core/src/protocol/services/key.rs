//! The services involved in the key forwarding flow.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{
	protocol::{
		ProtocolError, ProtocolState, QosHash,
		services::boot::{VersionedManifestEnvelope, put_manifest_and_pivot},
	},
	verify::{
		AttestationPolicy, ManifestCommitmentKind, VerificationExpectations,
		verify_attestation_and_manifest,
	},
};

const ATTESTATION_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// An encrypted quorum key along with a signature over the encrypted payload
/// from the sender.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct EncryptedQuorumKey {
	/// The encrypted payload: a quorum key
	#[serde(with = "qos_hex::serde")]
	pub encrypted_quorum_key: Vec<u8>,
	/// Signature over the encrypted quorum key
	#[serde(with = "qos_hex::serde")]
	pub signature: Vec<u8>,
}

pub(in crate::protocol) fn inject_key(
	state: &mut ProtocolState,
	EncryptedQuorumKey { encrypted_quorum_key, signature }: EncryptedQuorumKey,
) -> Result<(), ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;
	let manifest = manifest_envelope.manifest();

	// 1. Verify the signature over the `encrypted_quorum_key` against the
	// Quorum Key specified in the New Manifest.
	let quorum_public =
		P256Public::from_bytes(&manifest.namespace().quorum_key)?;
	quorum_public
		.verify(&encrypted_quorum_key, &signature)
		.map_err(|_| ProtocolError::InvalidEncryptedQuorumKeySignature)?;

	// 2. Decrypt the encrypted Quorum Key in the request with the Ephemeral
	// Key.
	let quorum_master_seed: zeroize::Zeroizing<
		[u8; qos_p256::MASTER_SEED_LEN],
	> = {
		let ephemeral_pair = state.handles.get_ephemeral_key()?;
		let bytes = ephemeral_pair.decrypt(&encrypted_quorum_key)?;
		zeroize::Zeroizing::new(
			bytes[..]
				.try_into()
				.map_err(|_| ProtocolError::EncryptedQuorumKeyInvalidLen)?,
		)
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
	let live_ephemeral_key = state.take_pending_live_ephemeral_key()?;
	state.handles.rotate_ephemeral_key(&live_ephemeral_key)?;

	// 5. Write the Quorum Key to the file system, at which point New Node will
	// automatically pivot to running the Pivot App.
	// (see `src/qos_core/src/reaper.rs`: we loop until the quorum key file exists)
	state.handles.put_quorum_key(&decrypted_quorum_pair)?;

	Ok(())
}

pub(in crate::protocol) fn boot_key_forward(
	state: &mut ProtocolState,
	manifest_envelope: impl Into<VersionedManifestEnvelope>,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	let manifest_envelope = manifest_envelope.into();
	let nsm_response =
		put_manifest_and_pivot(state, &manifest_envelope, pivot)?;
	Ok(nsm_response)
}

pub(in crate::protocol) fn export_key(
	state: &mut ProtocolState,
	new_manifest_envelope: impl Into<VersionedManifestEnvelope>,
	cose_sign1_attestation_document: &[u8],
) -> Result<EncryptedQuorumKey, ProtocolError> {
	let new_manifest_envelope = new_manifest_envelope.into();
	let old_manifest_envelope = state.handles.get_manifest_envelope()?;
	validate_manifest(&new_manifest_envelope, &old_manifest_envelope)?;
	let new_manifest = new_manifest_envelope.manifest();

	let root_ca = state.attestor.attestation_root_ca_der();
	let verified = verify_attestation_and_manifest(
		cose_sign1_attestation_document,
		&new_manifest,
		&AttestationPolicy::new(
			&root_ca,
			ATTESTATION_MAX_AGE,
			ManifestCommitmentKind::Setup,
		),
		&VerificationExpectations::new(),
	)
	.map_err(|err| ProtocolError::QosAttestError(err.to_string()))?;

	export_key_internal(state, &verified.ephemeral_key)
}

#[cfg(test)]
fn export_key_at_time(
	state: &mut ProtocolState,
	new_manifest_envelope: impl Into<VersionedManifestEnvelope>,
	cose_sign1_attestation_document: &[u8],
	current_time: Duration,
) -> Result<EncryptedQuorumKey, ProtocolError> {
	let new_manifest_envelope = new_manifest_envelope.into();
	let old_manifest_envelope = state.handles.get_manifest_envelope()?;
	validate_manifest(&new_manifest_envelope, &old_manifest_envelope)?;
	let new_manifest = new_manifest_envelope.manifest();

	let root_ca = state.attestor.attestation_root_ca_der();
	let verified =
		crate::verify::verify_attestation_and_manifest_at_time_for_test(
			cose_sign1_attestation_document,
			&new_manifest,
			&AttestationPolicy::new(
				&root_ca,
				ATTESTATION_MAX_AGE,
				ManifestCommitmentKind::Setup,
			),
			&VerificationExpectations::new(),
			current_time,
		)
		.map_err(|err| ProtocolError::QosAttestError(err.to_string()))?;

	export_key_internal(state, &verified.ephemeral_key)
}

fn export_key_internal(
	state: &mut ProtocolState,
	eph_key: &P256Public,
) -> Result<EncryptedQuorumKey, ProtocolError> {
	let quorum_key = state.handles.get_quorum_key()?;
	// 10. Return the Quorum Key encrypted to the New Node's Ephemeral Key
	// extracted from the attestation document and a signature over the
	// encrypted payload. The Original Node uses its Quorum Key to create the
	// signature.
	let encrypted_quorum_key =
		eph_key.encrypt(&quorum_key.to_master_seed()[..])?;
	let signature = quorum_key.sign(&encrypted_quorum_key)?;

	Ok(EncryptedQuorumKey { encrypted_quorum_key, signature })
}

/// Manifest validation logic. Extracted to make unit testing easier.
fn validate_manifest(
	new_manifest_envelope: impl Into<VersionedManifestEnvelope>,
	old_manifest_envelope: impl Into<VersionedManifestEnvelope>,
) -> Result<(), ProtocolError> {
	let new_manifest_envelope = new_manifest_envelope.into();
	let old_manifest_envelope = old_manifest_envelope.into();
	// 2. Check the signatures over the New Manifest. Ensures that K Manifest
	// Set Members approved the New Manifest.
	new_manifest_envelope.check_approvals()?;

	if !new_manifest_envelope.share_set_approvals().is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}

	let new_manifest = new_manifest_envelope.manifest();
	let old_manifest = old_manifest_envelope.manifest();

	// 3. Check that the Quorum Key of the Local Manifest matches the Quorum Key
	// of the New Manifest. This ensures the request is for the correct Quorum
	// Key.
	if old_manifest.namespace().quorum_key
		!= new_manifest.namespace().quorum_key
	{
		return Err(ProtocolError::DifferentQuorumKey {
			expected: qos_hex::encode(&old_manifest.namespace().quorum_key),
			actual: qos_hex::encode(&new_manifest.namespace().quorum_key),
		});
	}

	// 4. Check that the Manifest Set of the New Manifest matches the Manifest
	// Set of the Local Manifest. Ensures that the signatures are from a trusted
	// Manifest Set. Note that there is still a vulnerability here if we have
	// try to retire a Manifest Set because a critical threshold of it was
	// compromised - that malicious Manifest Set could boot off of an Original
	// Node - thus it's important to retire all Original Nodes ASAP that use
	// compromised Manifest Sets.
	{
		let mut old_members = old_manifest.manifest_set().members.clone();
		let mut new_members = new_manifest.manifest_set().members.clone();
		old_members.sort();
		new_members.sort();
		if old_manifest.manifest_set().threshold
			!= new_manifest.manifest_set().threshold
			|| old_members != new_members
		{
			let old_set = crate::protocol::services::boot::ManifestSet {
				threshold: old_manifest.manifest_set().threshold,
				members: old_members,
			};
			let new_set = crate::protocol::services::boot::ManifestSet {
				threshold: new_manifest.manifest_set().threshold,
				members: new_members,
			};
			return Err(ProtocolError::DifferentManifestSet {
				expected: qos_hex::encode(&old_set.qos_hash()),
				actual: qos_hex::encode(&new_set.qos_hash()),
			});
		}
	}

	// 5. Check that the Namespace of the Local Manifest matches the namespace
	// of the New Manifest. Namespaces are a social construct, but we only want
	// to allow forwarding a Quorum Key to Nodes in the same Namespace to help
	// ensure that the nonce is not abused.
	if old_manifest.namespace().name != new_manifest.namespace().name {
		return Err(ProtocolError::DifferentNamespaceName {
			expected: old_manifest.namespace().name.clone(),
			actual: new_manifest.namespace().name.clone(),
		});
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
	if old_manifest.namespace().nonce > new_manifest.namespace().nonce {
		return Err(ProtocolError::LowNonce {
			expected: old_manifest.namespace().nonce,
			actual: new_manifest.namespace().nonce,
		});
	} else if old_manifest.namespace().nonce == new_manifest.namespace().nonce
		&& old_manifest.manifest_hash() != new_manifest.manifest_hash()
	{
		return Err(ProtocolError::DifferentManifest {
			expected: qos_hex::encode(&old_manifest.manifest_hash()),
			actual: qos_hex::encode(&new_manifest.manifest_hash()),
		});
	}

	// 7. Check that PCR3 in the New Manifest is in the Local Manifests. PCR3 is
	// the IAM role assigned to the EC2 host of the enclave. An IAM role
	// contains an AWS organization's unique ID. By only using the approved PCR3
	// value we ensure that we only ever send the Quorum Key to an enclave that
	// is controlled by the operator, not an enclave that some malicious entity
	// runs that otherwise configured identically to one of the operator's
	// enclaves.
	if old_manifest.enclave().pcr3 != new_manifest.enclave().pcr3 {
		return Err(ProtocolError::DifferentPcr3 {
			expected: qos_hex::encode(&old_manifest.enclave().pcr3),
			actual: qos_hex::encode(&new_manifest.enclave().pcr3),
		});
	}

	Ok(())
}

#[cfg(test)]
mod test {
	use std::time::Duration;

	use qos_crypto::sha_256;
	use qos_nsm::{
		NsmProvider,
		mock::{MOCK_SECONDS_SINCE_EPOCH, MockNsm},
		nitro,
		types::{NsmRequest, NsmResponse},
	};
	use qos_p256::P256Pair;
	use qos_test_primitives::PathWrapper;

	use super::{
		boot_key_forward, export_key_at_time, export_key_internal,
		validate_manifest,
	};
	use crate::{
		handles::Handles,
		protocol::{
			ProtocolError, ProtocolPhase, ProtocolState, QosHash,
			services::{
				boot::{
					Approval, Manifest, ManifestEnvelope, ManifestSet,
					Namespace, NitroConfig, PivotConfig, QuorumMember,
					RestartPolicy, ShareSet,
				},
				key::{EncryptedQuorumKey, inject_key},
			},
		},
	};

	struct TestArgs {
		manifest_envelope: ManifestEnvelope,
		eph_pair: P256Pair,
		quorum_pair: P256Pair,
		pivot: Vec<u8>,
	}

	#[allow(clippy::too_many_lines)]
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

		let members_with_keys = [
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
				..Default::default()
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

		let eph_pair = P256Pair::generate().unwrap();

		let manifest_envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals,
			share_set_approvals: Vec::default(),
		};

		TestArgs { manifest_envelope, eph_pair, quorum_pair, pivot }
	}

	mod boot_key_forward {
		use super::*;

		#[test]
		fn accepts_approved_manifest() {
			let TestArgs { manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file = PathWrapper::from(
				"/tmp/boot_key_forward_accepts_approved_manifest.pivot",
			);
			let ephemeral_file = PathWrapper::from(
				"/tmp/boot_key_accepts_approved_manifest.eph.secret",
			);
			let manifest_file = PathWrapper::from(
				"/tmp/boot_key_accepts_approved_manifest.manifest",
			);

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				"qorum".to_string(),
				manifest_file.display().to_string(),
				pivot_file.display().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm::new()),
				handles.clone(),
				None,
			);

			let response =
				boot_key_forward(&mut state, &manifest_envelope, &pivot)
					.unwrap();
			if let NsmResponse::Attestation { document } = response {
				assert!(!document.is_empty());
			} else {
				panic!()
			}

			assert!(handles.pivot_exists());
			assert_eq!(
				handles.get_manifest_envelope().unwrap(),
				crate::protocol::services::boot::VersionedManifestEnvelope::V1(
					manifest_envelope,
				)
			);

			handles.get_ephemeral_key().unwrap();
		}

		#[test]
		fn rejects_manifest_if_not_enough_approvals() {
			let TestArgs { mut manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.pivot",
			);
			let ephemeral_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.secret",
			);
			let manifest_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_not_enough_approvals.manifest",
			);

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				"qorum".to_string(),
				manifest_file.display().to_string(),
				pivot_file.display().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm::new()),
				handles.clone(),
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

			let pivot_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.pivot",
			);
			let ephemeral_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.secret",
			);
			let manifest_file = PathWrapper::from(
				"/tmp/boot_key_rejects_manifest_if_wrong_pivot_hash.manifest",
			);

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				"qorum".to_string(),
				manifest_file.display().to_string(),
				pivot_file.display().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm::new()),
				handles.clone(),
				None,
			);

			// Use a different pivot then what is referenced in the manifest
			let other_pivot = b"other pivot".to_vec();
			let err =
				boot_key_forward(&mut state, &manifest_envelope, &other_pivot);
			assert!(
				matches!(err, Err(ProtocolError::InvalidPivotHash { .. })),
				"expected InvalidPivotHash error, got {err:?}"
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
		fn rejects_manifest_with_bad_approval_signature() {
			let TestArgs { mut manifest_envelope, pivot, .. } = get_test_args();

			let pivot_file = PathWrapper::from(
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.pivot",
			);
			let ephemeral_file = PathWrapper::from(
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.secret",
			);
			let manifest_file = PathWrapper::from(
				"/tmp/boot_key_rejects_rejects_manifest_with_bad_approval_signature.manifest",
			);

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				"quorum".to_string(),
				manifest_file.display().to_string(),
				pivot_file.display().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm::new()),
				handles.clone(),
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

			let pivot_file = PathWrapper::from(
				"/tmp/boot_key_reject_manifest_with_approval_from_non_memberpivot",
			);
			let ephemeral_file = PathWrapper::from(
				"/tmp/boot_key_reject_manifest_with_approval_from_non_membersecret",
			);
			let manifest_file = PathWrapper::from(
				"/tmp/boot_key_reject_manifest_with_approval_from_non_membermanifest",
			);

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				"quorum".to_string(),
				manifest_file.display().to_string(),
				pivot_file.display().to_string(),
			);
			let mut state = ProtocolState::new(
				Box::new(MockNsm::new()),
				handles.clone(),
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
			let TestArgs { manifest_envelope, .. } = get_test_args();
			assert!(
				validate_manifest(&manifest_envelope, &manifest_envelope,)
					.is_ok()
			);
		}

		#[test]
		fn accepts_manifest_with_greater_nonce() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,)
					.is_ok()
			);
		}

		#[test]
		fn rejects_manifest_with_lower_nonce() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.nonce += 1;

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::LowNonce { .. })
			));
		}

		#[test]
		fn rejects_manifest_with_matching_nonce_different_hash() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.enclave.pcr0 = vec![128; 32];

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentManifest { .. })
			));
		}

		#[test]
		fn rejects_manifest_with_different_quorum_key() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			let different_quorum_key =
				P256Pair::generate().unwrap().public_key().to_bytes();
			old_manifest_envelope.manifest.namespace.quorum_key =
				different_quorum_key;

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentQuorumKey { .. })
			));
		}

		#[test]
		fn does_not_accept_manifest_with_different_manifest_set() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.manifest_set.members.pop();
			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentManifestSet { .. })
			));

			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.manifest_set.threshold = 1;
			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentManifestSet { .. })
			));
		}

		#[test]
		fn accepts_manifest_with_different_ordered_manifest_set_members() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			let last_member =
				old_manifest_envelope.manifest.manifest_set.members.remove(2);
			old_manifest_envelope
				.manifest
				.manifest_set
				.members
				.insert(0, last_member);

			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,)
					.is_ok(),
			);
		}

		#[test]
		fn rejects_manifest_with_different_namespace_name() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.namespace.name =
				"other namespace".to_string();

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentNamespaceName { .. }),
			));
		}

		#[test]
		fn reject_manifest_with_different_pcr3() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut old_manifest_envelope = manifest_envelope.clone();
			old_manifest_envelope.manifest.enclave.pcr3 = vec![128; 32];
			old_manifest_envelope.manifest.namespace.nonce -= 1;

			assert!(matches!(
				validate_manifest(&manifest_envelope, &old_manifest_envelope,),
				Err(ProtocolError::DifferentPcr3 { .. }),
			));
		}

		#[test]
		fn errors_with_two_few_manifest_approvals() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();

			new_manifest_envelope.manifest_set_approvals.pop().unwrap();
			assert_eq!(
				validate_manifest(&new_manifest_envelope, &manifest_envelope,),
				Err(ProtocolError::NotEnoughApprovals)
			);
		}

		#[test]
		fn rejects_manifest_with_bad_approval_signature() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
			let mut new_manifest_envelope = manifest_envelope.clone();

			new_manifest_envelope.manifest_set_approvals[0].signature =
				vec![1; 32];
			let bad_approval =
				new_manifest_envelope.manifest_set_approvals[0].clone();

			assert_eq!(
				validate_manifest(&new_manifest_envelope, &manifest_envelope,),
				Err(ProtocolError::InvalidManifestApproval(bad_approval))
			);
		}

		#[test]
		fn rejects_manifest_with_approval_from_non_member() {
			let TestArgs { manifest_envelope, .. } = get_test_args();
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
				validate_manifest(&new_manifest_envelope, &manifest_envelope,),
				Err(ProtocolError::NotManifestSetMember)
			);
		}
	}

	mod export_key_inner {
		use super::*;
		use crate::protocol::services::key::EncryptedQuorumKey;

		/// Set up handles for an "old" enclave that has a manifest, quorum
		/// key, and its own ephemeral key on disk.
		fn setup_export_key_handles(
			name: &str,
			manifest_envelope: &ManifestEnvelope,
			quorum_pair: &P256Pair,
		) -> Handles {
			let temp_dir = std::env::temp_dir();
			let ephemeral_file = temp_dir
				.join(format!("{name}.eph.secret"))
				.to_string_lossy()
				.into_owned();
			let quorum_file = temp_dir
				.join(format!("{name}.quorum.secret"))
				.to_string_lossy()
				.into_owned();
			let manifest_file = temp_dir
				.join(format!("{name}.manifest"))
				.to_string_lossy()
				.into_owned();

			P256Pair::generate().unwrap().to_hex_file(&ephemeral_file).unwrap();
			quorum_pair.to_hex_file(&quorum_file).unwrap();
			std::fs::write(
				&manifest_file,
				serde_json::to_vec(manifest_envelope).unwrap(),
			)
			.unwrap();

			Handles::new(
				ephemeral_file,
				quorum_file,
				manifest_file,
				"pivot".to_string(),
			)
		}

		/// Build a mock NSM whose PCR bank matches the manifest measurements
		/// and setup commitment, mirroring the state of a "new" enclave that
		/// booted with `manifest_envelope` and `eph_pair`.
		fn new_enclave_mock_nsm(
			manifest_envelope: &ManifestEnvelope,
			eph_pair: &P256Pair,
		) -> MockNsm {
			let manifest = &manifest_envelope.manifest;
			let setup_commitment_pcr = nitro::expected_manifest_commitment_pcr(
				nitro::ManifestCommitmentKind::Setup,
				&manifest.qos_hash(),
				&eph_pair.public_key().to_bytes(),
			)
			.unwrap();

			MockNsm::new()
				.with_pcr(0, manifest.enclave.pcr0.clone())
				.with_pcr(1, manifest.enclave.pcr1.clone())
				.with_pcr(2, manifest.enclave.pcr2.clone())
				.with_pcr(3, manifest.enclave.pcr3.clone())
				.with_pcr(
					nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
					setup_commitment_pcr.to_vec(),
				)
		}

		/// Request a signed attestation document like a "new" enclave would
		/// return from a key forward boot.
		fn signed_attestation_document(
			nsm: &MockNsm,
			manifest_envelope: &ManifestEnvelope,
			eph_pair: &P256Pair,
		) -> Vec<u8> {
			let NsmResponse::Attestation { document } = nsm
				.nsm_process_request(NsmRequest::Attestation {
					user_data: Some(
						manifest_envelope.manifest.qos_hash().to_vec(),
					),
					nonce: None,
					public_key: Some(eph_pair.public_key().to_bytes()),
				})
			else {
				panic!("expected attestation response");
			};
			document
		}

		#[test]
		fn export_key_works_with_fully_verified_attestation_doc() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();
			let handles = setup_export_key_handles(
				"export_key_works_with_fully_verified_attestation_doc",
				&manifest_envelope,
				&quorum_pair,
			);

			let nsm = new_enclave_mock_nsm(&manifest_envelope, &eph_pair);
			let document = signed_attestation_document(
				&nsm,
				&manifest_envelope,
				&eph_pair,
			);

			let mut state = ProtocolState::new(Box::new(nsm), handles, None);
			let EncryptedQuorumKey { encrypted_quorum_key, signature } =
				export_key_at_time(
					&mut state,
					&manifest_envelope,
					&document,
					Duration::from_secs(MOCK_SECONDS_SINCE_EPOCH),
				)
				.unwrap();

			// quorum key signature over payload is valid
			assert!(
				quorum_pair
					.public_key()
					.verify(&encrypted_quorum_key, &signature)
					.is_ok()
			);
			// the quorum key was encrypted to the *attested* ephemeral key
			let decrypted_quorum_secret =
				eph_pair.decrypt(&encrypted_quorum_key).unwrap();
			let reconstructed_quorum_pair =
				P256Pair::from_master_seed(&zeroize::Zeroizing::new(
					decrypted_quorum_secret[..].try_into().unwrap(),
				))
				.unwrap();
			assert!(quorum_pair == reconstructed_quorum_pair);
		}

		#[test]
		fn export_key_rejects_doc_not_signed_by_the_trusted_root() {
			/// A provider that serves mock-signed attestation docs but
			/// trusts the (default) AWS Nitro root when verifying peers.
			struct AwsRootMockNsm(MockNsm);
			impl NsmProvider for AwsRootMockNsm {
				fn nsm_process_request(
					&self,
					request: NsmRequest,
				) -> NsmResponse {
					self.0.nsm_process_request(request)
				}
				fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
					self.0.timestamp_ms()
				}
				// `attestation_root_ca_der` is intentionally NOT overridden:
				// the default is the AWS Nitro root CA.
			}

			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();
			let handles = setup_export_key_handles(
				"export_key_rejects_doc_not_signed_by_the_trusted_root",
				&manifest_envelope,
				&quorum_pair,
			);

			let nsm = new_enclave_mock_nsm(&manifest_envelope, &eph_pair);
			let document = signed_attestation_document(
				&nsm,
				&manifest_envelope,
				&eph_pair,
			);

			let mut state = ProtocolState::new(
				Box::new(AwsRootMockNsm(nsm)),
				handles,
				None,
			);
			let Err(err) = export_key_at_time(
				&mut state,
				&manifest_envelope,
				&document,
				Duration::from_secs(MOCK_SECONDS_SINCE_EPOCH),
			) else {
				panic!("expected export_key to reject the document");
			};

			assert!(matches!(err, ProtocolError::QosAttestError(_)));
		}

		#[test]
		fn export_key_rejects_doc_with_wrong_pcrs() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();
			let handles = setup_export_key_handles(
				"export_key_rejects_doc_with_wrong_pcrs",
				&manifest_envelope,
				&quorum_pair,
			);

			// PCR0 does not match the manifest.
			let nsm = new_enclave_mock_nsm(&manifest_envelope, &eph_pair)
				.with_pcr(0, vec![128; 32]);
			let document = signed_attestation_document(
				&nsm,
				&manifest_envelope,
				&eph_pair,
			);

			let mut state = ProtocolState::new(Box::new(nsm), handles, None);
			let Err(err) = export_key_at_time(
				&mut state,
				&manifest_envelope,
				&document,
				Duration::from_secs(MOCK_SECONDS_SINCE_EPOCH),
			) else {
				panic!("expected export_key to reject the document");
			};

			assert!(matches!(err, ProtocolError::QosAttestError(_)));
		}

		#[test]
		fn works() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file =
				PathWrapper::from("export_key_inner_works.eph.secret");
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();

			let manifest_file =
				PathWrapper::from("export_key_inner_works.manifest");

			let quorum_file =
				PathWrapper::from("export_key_inner_works.quorum.secret");
			quorum_pair.to_hex_file(&*quorum_file).unwrap();

			std::fs::write(
				&*manifest_file,
				serde_json::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();
			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				quorum_file.display().to_string(),
				manifest_file.display().to_string(),
				"pivot".to_string(),
			);

			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);
			let EncryptedQuorumKey { encrypted_quorum_key, signature } =
				export_key_internal(
					&mut protocol_state,
					&eph_pair.public_key(),
				)
				.unwrap();

			// quorum key signature over payload is valid
			assert!(
				quorum_pair
					.public_key()
					.verify(&encrypted_quorum_key, &signature)
					.is_ok()
			);

			let decrypted_quorum_secret =
				eph_pair.decrypt(&encrypted_quorum_key).unwrap();
			let reconstructed_quorum_pair =
				P256Pair::from_master_seed(&zeroize::Zeroizing::new(
					decrypted_quorum_secret[..].try_into().unwrap(),
				))
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

			let ephemeral_file =
				PathWrapper::from("inject_key_works.eph.secret");
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file = PathWrapper::from("inject_key_works.manifest");
			let quorum_file =
				PathWrapper::from("inject_key_works.quorum.secret");
			std::fs::write(
				&*manifest_file,
				serde_json::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();

			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(&quorum_pair.to_master_seed()[..])
				.unwrap();
			let signature = quorum_pair.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				quorum_file.display().to_string(),
				manifest_file.display().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);
			let live_eph_pair = P256Pair::generate().unwrap();
			protocol_state
				.set_pending_live_ephemeral_key(live_eph_pair.clone());
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
			assert_eq!(
				new_eph_key,
				live_eph_pair.to_master_seed_hex().as_slice()
			);
		}

		#[test]
		fn rejects_wrong_encrypted_key() {
			let TestArgs { manifest_envelope, eph_pair, quorum_pair, .. } =
				get_test_args();

			let ephemeral_file =
				PathWrapper::from("inject_rejects_bad_signature.eph.secret");
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file =
				PathWrapper::from("inject_rejects_bad_signature.manifest");
			let quorum_file =
				PathWrapper::from("inject_rejects_bad_signature.quorum.secret");
			std::fs::write(
				&*manifest_file,
				serde_json::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();

			let wrong_key = P256Pair::generate().unwrap();
			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(&wrong_key.to_master_seed()[..])
				.unwrap();
			let signature = quorum_pair.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				quorum_file.display().to_string(),
				manifest_file.display().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);

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

			let ephemeral_file = PathWrapper::from(
				"inject_key_rejects_wrong_quorum_key.eph.secret",
			);
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file = PathWrapper::from(
				"inject_key_rejects_wrong_quorum_key.manifest",
			);
			let quorum_file = PathWrapper::from(
				"inject_key_rejects_wrong_quorum_key.quorum.secret",
			);
			std::fs::write(
				&*manifest_file,
				serde_json::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();

			let wrong_key = P256Pair::generate().unwrap();
			let encrypted_quorum_key = eph_pair
				.public_key()
				.encrypt(&quorum_pair.to_master_seed()[..])
				.unwrap();
			let signature = wrong_key.sign(&encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				quorum_file.display().to_string(),
				manifest_file.display().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);

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

			let ephemeral_file = PathWrapper::from(
				"inject_key_rejects_invalid_quorum_key.eph.secret",
			);
			eph_pair.to_hex_file(&*ephemeral_file).unwrap();
			let manifest_file = PathWrapper::from(
				"inject_key_rejects_invalid_quorum_key.manifest",
			);
			let quorum_file = PathWrapper::from(
				"inject_key_rejects_invalid_quorum_key.quorum.secret",
			);
			std::fs::write(
				&*manifest_file,
				serde_json::to_vec(&manifest_envelope).unwrap(),
			)
			.unwrap();

			let mut invalid_master_seed =
				zeroize::Zeroizing::new(quorum_pair.to_master_seed().to_vec());
			invalid_master_seed.remove(0);
			let invalid_encrypted_quorum_key =
				eph_pair.public_key().encrypt(&invalid_master_seed).unwrap();
			let signature =
				quorum_pair.sign(&invalid_encrypted_quorum_key).unwrap();

			let handles = Handles::new(
				ephemeral_file.display().to_string(),
				quorum_file.display().to_string(),
				manifest_file.display().to_string(),
				"pivot".to_string(),
			);
			let mut protocol_state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);

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
