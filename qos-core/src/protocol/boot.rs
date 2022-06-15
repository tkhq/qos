use borsh::BorshSerialize;
use qos_crypto::{sha_256, RsaPair, RsaPub};

use super::{
	Hash256, NsmRequest, NsmResponse, ProtocolError, ProtocolPhase,
	ProtocolState,
};

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct NitroConfig {
	/// VSOCK Context ID - component of VSockAddress.
	pub vsock_cid: u16,
	/// VSOCK Port - component of VSockAddress.
	pub vsock_port: u16,
	/// The hash of the enclave image file
	pub pcr0: Hash256,
	/// The hash of the Linux kernel and bootstrap
	pub pcr1: Hash256,
	/// The hash of the application
	pub pcr2: Hash256,
	/// DER encoded X509 AWS root certificate
	pub aws_root_certificate: Vec<u8>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum RestartPolicy {
	/// Never restart the pivot application
	Never,
	/// Always restart the pivot application
	Always,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct PivotConfig {
	pub hash: Hash256,
	pub restart: RestartPolicy,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct QuorumMember {
	pub alias: String,
	/// DER encoded RSA public key
	pub pub_key: Vec<u8>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct QuorumSet {
	pub threshold: u32,
	pub members: Vec<QuorumMember>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Manifest {
	pub nonce: u32,
	pub namespace: String,
	pub enclave: NitroConfig,
	pub pivot: PivotConfig,
	pub quorum_key: Vec<u8>,
	pub quorum_set: QuorumSet,
}

impl Manifest {
	pub fn hash(&self) -> Hash256 {
		qos_crypto::sha_256(
			&self.try_to_vec().expect("`Manifest` serializes with cbor"),
		)
	}
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Approval {
	pub signature: Vec<u8>,
	pub member: QuorumMember,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct ManifestEnvelope {
	pub manifest: Manifest,
	pub approvals: Vec<Approval>,
}

impl ManifestEnvelope {
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		for approval in self.approvals.iter() {
			let pub_key = RsaPub::from_der(&approval.member.pub_key)
				.map_err(|_| ProtocolError::CryptoError)?;

			let is_valid_signature = pub_key
				.verify_sha256(&approval.signature, &self.manifest.hash())
				.map_err(|_| ProtocolError::CryptoError)?;
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				))
			}
		}

		if self.approvals.len() < self.manifest.quorum_set.threshold as usize {
			return Err(ProtocolError::NotEnoughApprovals)
		}

		Ok(())
	}
}

pub fn boot_standard(
	state: &mut ProtocolState,
	manifest_envelope: ManifestEnvelope,
	pivot: &Vec<u8>,
) -> Result<NsmResponse, ProtocolError> {
	use std::os::unix::fs::PermissionsExt as _;

	manifest_envelope.check_approvals()?;

	let ephemeral_key = RsaPair::generate()?;
	std::fs::write(
		state.ephemeral_key_file.clone(),
		ephemeral_key.private_key_to_der()?,
	)?;

	if sha_256(pivot) != manifest_envelope.manifest.pivot.hash {
		return Err(ProtocolError::InvalidPivotHash)
	};

	std::fs::write(&state.pivot_file, pivot)?;
	std::fs::set_permissions(
		&state.pivot_file,
		std::fs::Permissions::from_mode(0o111),
	)?;

	state.manifest = Some(manifest_envelope.clone());

	let nsm_response = {
		let request = NsmRequest::Attestation {
			// TODO: make sure CLI verifies the manifest hash is correct
			user_data: Some(manifest_envelope.manifest.hash().to_vec()),
			nonce: None,
			public_key: Some(ephemeral_key.public_key_to_pem().unwrap()),
		};
		let fd = state.attestor.nsm_init();

		state.attestor.nsm_process_request(fd, request)
	};

	state.phase = ProtocolPhase::WaitingForQuorumShards;

	Ok(nsm_response)
}

#[cfg(test)]
mod test {
	use std::path::Path;

	use super::*;
	use crate::protocol::MockNsm;

	fn get_manifest() -> (Manifest, Vec<(RsaPair, QuorumMember)>, Vec<u8>) {
		let quorum_pair = RsaPair::generate().unwrap();
		let member1_pair = RsaPair::generate().unwrap();
		let member2_pair = RsaPair::generate().unwrap();
		let member3_pair = RsaPair::generate().unwrap();

		let pivot = b"this is a pivot binary".to_vec();

		let quorum_members = vec![
			QuorumMember {
				alias: "member1".to_string(),
				pub_key: member1_pair.public_key_to_der().unwrap(),
			},
			QuorumMember {
				alias: "member2".to_string(),
				pub_key: member2_pair.public_key_to_der().unwrap(),
			},
			QuorumMember {
				alias: "member3".to_string(),
				pub_key: member3_pair.public_key_to_der().unwrap(),
			},
		];

		let member_with_keys = vec![
			(member1_pair, quorum_members.get(0).unwrap().clone()),
			(member2_pair, quorum_members.get(1).unwrap().clone()),
			(member3_pair, quorum_members.get(2).unwrap().clone()),
		];

		let manifest = Manifest {
			nonce: 420,
			namespace: "vape lord".to_string(),
			enclave: NitroConfig {
				vsock_cid: 69,
				vsock_port: 42069,
				pcr0: [4; 32],
				pcr1: [2; 32],
				pcr2: [0; 32],
				aws_root_certificate: b"cert lord".to_vec(),
			},
			pivot: PivotConfig {
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
			},
			quorum_key: quorum_pair.public_key_to_der().unwrap(),
			quorum_set: QuorumSet {
				threshold: 2,
				members: quorum_members.clone(),
			},
		};

		(manifest, member_with_keys, pivot)
	}

	#[test]
	fn manifest_hash() {
		let (manifest, _members, _pivot) = get_manifest();

		let hashes: Vec<_> = (0..10).map(|_| manifest.hash()).collect();
		let is_valid = (1..10).all(|i| hashes[i] == hashes[0]);
		assert!(is_valid);
	}

	#[test]
	fn boot_standard_accepts_approved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.hash();
			let approvals = members
				.into_iter()
				.map(|(pair, member)| {
					return Approval {
						signature: pair.sign_sha256(&manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();

			ManifestEnvelope { manifest, approvals }
		};

		let pivot_file =
			"boot_standard_accepts_approved_manifest.pivot".to_string();
		let ephemeral_file =
			"boot_standard_accepts_approved_manifest_eph.secret".to_string();
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			"secret".to_string(),
			pivot_file.clone(),
			ephemeral_file.clone(),
		);

		let _nsm_resposne =
			boot_standard(&mut protocol_state, manifest_envelope, &pivot)
				.unwrap();

		assert!(Path::new(&pivot_file).exists());
		assert!(Path::new(&ephemeral_file).exists());

		std::fs::remove_file(pivot_file).unwrap();
		std::fs::remove_file(ephemeral_file).unwrap();

		assert_eq!(protocol_state.phase, ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn boot_standard_rejects_manifest_if_not_enough_approvals() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.hash();
			let approvals = members
				[0usize..manifest.quorum_set.threshold as usize - 1]
				.into_iter()
				.map(|(pair, member)| {
					return Approval {
						signature: pair.sign_sha256(&manifest_hash).unwrap(),
						member: member.clone(),
					}
				})
				.collect();

			ManifestEnvelope { manifest, approvals }
		};

		let pivot_file = "boot_standard_works.pivot".to_string();
		let ephemeral_file = "boot_standard_works_eph.secret".to_string();
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			"secret".to_string(),
			pivot_file.clone(),
			ephemeral_file.clone(),
		);

		let nsm_resposne =
			boot_standard(&mut protocol_state, manifest_envelope, &pivot);

		assert!(nsm_resposne.is_err());
	}

	#[test]
	fn boot_standard_rejects_unapproved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let approvals = members
				.into_iter()
				.map(|(_pair, member)| {
					return Approval {
						signature: vec![0, 0],
						member: member.clone(),
					}
				})
				.collect();

			ManifestEnvelope { manifest, approvals }
		};

		let pivot_file = "boot_standard_works.pivot".to_string();
		let ephemeral_file = "boot_standard_works_eph.secret".to_string();
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			"secret".to_string(),
			pivot_file.clone(),
			ephemeral_file.clone(),
		);

		let nsm_resposne =
			boot_standard(&mut protocol_state, manifest_envelope, &pivot);

		assert!(nsm_resposne.is_err());
	}
}
