//! Quorum Key provisioning logic and types.
use qos_p256::P256Pair;

use crate::protocol::{
	services::boot::Approval, ProtocolError, ProtocolState, QosHash,
};

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

/// Shamir Secret builder.
pub(crate) struct SecretBuilder {
	shares: Shares,
}

impl SecretBuilder {
	/// Create a instance of [`Self`].
	pub fn new() -> Self {
		Self { shares: Vec::new() }
	}

	/// Add a share to later be used to reconstruct.
	pub(crate) fn add_share(
		&mut self,
		share: Share,
	) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}

		self.shares.push(share);
		Ok(())
	}

	/// Attempt to reconstruct the secret from the
	pub(crate) fn build(&self) -> Result<Secret, ProtocolError> {
		let secret = qos_crypto::shamir::shares_reconstruct(&self.shares)
			.map_err(|e| ProtocolError::QosCrypto(format!("{e:?}")))?;

		if secret.is_empty() {
			return Err(ProtocolError::ReconstructionErrorEmptySecret);
		}

		Ok(secret)
	}

	/// The count of shares.
	pub(crate) fn count(&self) -> usize {
		self.shares.len()
	}

	pub(crate) fn clear(&mut self) {
		self.shares = vec![];
	}
}

pub(in crate::protocol) fn provision(
	encrypted_share: &[u8],
	approval: Approval,
	state: &mut ProtocolState,
) -> Result<bool, ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;

	// Check that the approval is valid
	// 1) the signature is valid. Note that we want to check signature before
	// interacting with data
	approval.verify(&manifest_envelope.manifest.qos_hash())?;
	// 2) the approver belongs to the share set
	if !manifest_envelope.manifest.share_set.members.contains(&approval.member)
	{
		return Err(ProtocolError::NotShareSetMember {
			member_alias: approval.member.alias.clone(),
			member_pub_key: qos_hex::encode(&approval.member.pub_key),
			expected_members: format!(
				"{:?}",
				manifest_envelope.manifest.share_set.members
			),
		});
	}

	// Record the share set approval
	state.handles.mutate_manifest_envelope(|mut envelope| {
		envelope.share_set_approvals.push(approval);
		envelope
	})?;

	let ephemeral_key = state.handles.get_ephemeral_key()?;

	let share = ephemeral_key
		.decrypt(encrypted_share)
		.map_err(|_| ProtocolError::DecryptionFailed)?;

	state.provisioner.add_share(share)?;

	let quorum_threshold =
		manifest_envelope.manifest.share_set.threshold as usize;
	if state.provisioner.count() < quorum_threshold {
		// Nothing else to do if we don't have the threshold to reconstruct
		return Ok(false);
	}

	let master_seed = state.provisioner.build()?;
	state.provisioner.clear();

	let master_seed: [u8; qos_p256::MASTER_SEED_LEN] =
		master_seed
			.try_into()
			.map_err(|_| ProtocolError::IncorrectSecretLen)?;
	let pair = qos_p256::P256Pair::from_master_seed(&master_seed)?;
	let public_key_bytes = pair.public_key().to_bytes();

	if public_key_bytes != manifest_envelope.manifest.namespace.quorum_key {
		// We did not construct the intended key
		return Err(ProtocolError::ReconstructionErrorIncorrectPubKey);
	}

	// Rotate the ephemeral key so it's safe for apps to use it independently
	// of boot-related operations, which use the pre-boot ephemeral key as
	// an encryption target (boot standard flow encrypts quorum key shares to it.)
	let new_ephemeral_key = P256Pair::generate()?;
	state.handles.rotate_ephemeral_key(&new_ephemeral_key)?;

	// Write the quorum key to the file system.
	// Note: it's important to do this _last_, because the enclave will
	// automatically pivot to running the Pivot App once the file exists.
	// (see `src/qos_core/src/reaper.rs`: we loop until the quorum key file exists)
	state.handles.put_quorum_key(&pair)?;

	Ok(true)
}

#[cfg(test)]
mod test {
	use std::path::Path;

	use qos_crypto::{sha_256, shamir::shares_generate};
	use qos_nsm::mock::MockNsm;
	use qos_p256::P256Pair;
	use qos_test_primitives::PathWrapper;

	use crate::{
		handles::Handles,
		protocol::{
			services::{
				boot::{
					Approval, Manifest, ManifestEnvelope, ManifestSet,
					Namespace, NitroConfig, PatchSet, PivotConfig,
					QuorumMember, RestartPolicy, ShareSet,
				},
				provision::provision,
			},
			ProtocolError, ProtocolPhase, ProtocolState, QosHash,
		},
	};

	struct Setup {
		quorum_pair: P256Pair,
		eph_pair: P256Pair,
		threshold: usize,
		state: ProtocolState,
		approvals: Vec<Approval>,
	}

	fn setup(eph_file: &str, quorum_file: &str, manifest_file: &str) -> Setup {
		let handles = Handles::new(
			eph_file.to_string(),
			quorum_file.to_string(),
			manifest_file.to_string(),
			"pivot".to_string(),
		);
		// 1) Create and write eph key
		let eph_pair = P256Pair::generate().unwrap();
		handles.put_ephemeral_key(&eph_pair).unwrap();
		// 2) Create and write manifest with threshold and quorum key
		let quorum_pair = P256Pair::generate().unwrap();
		let threshold = 3usize;
		let pivot = b"this is a pivot binary";

		let members: Vec<_> = (0..4)
			.map(|_| P256Pair::generate().unwrap())
			.enumerate()
			.map(|(i, pair)| {
				let member = QuorumMember {
					alias: i.to_string(),
					pub_key: pair.public_key().to_bytes(),
				};

				(member, pair)
			})
			.collect();

		let manifest = Manifest {
			namespace: Namespace {
				nonce: 420,
				name: "vape-space".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
			},
			pivot: PivotConfig {
				hash: sha_256(pivot),
				restart: RestartPolicy::Always,
				args: vec![],
				..Default::default()
			},
			manifest_set: ManifestSet {
				threshold: threshold.try_into().unwrap(),
				members: vec![],
			},
			share_set: ShareSet {
				threshold: threshold.try_into().unwrap(),
				members: members.clone().into_iter().map(|(m, _)| m).collect(),
			},
			patch_set: PatchSet::default(),
			..Default::default()
		};

		let approvals: Vec<_> = members
			.into_iter()
			.map(|(member, pair)| {
				let approval = Approval {
					member,
					signature: pair.sign(&manifest.qos_hash()).unwrap(),
				};

				assert!(approval.verify(&manifest.qos_hash()).is_ok());

				approval
			})
			.collect();

		let manifest_envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		handles.put_manifest_envelope(&manifest_envelope).unwrap();

		// 3) Create state with eph key and manifest
		let mut state = ProtocolState::new(Box::new(MockNsm), handles, None);
		state.transition(ProtocolPhase::WaitingForQuorumShards).unwrap();

		Setup { quorum_pair, eph_pair, threshold, state, approvals }
	}

	#[test]
	fn provision_works() {
		let quorum_file: PathWrapper = "./provision_works.quorum.key".into();
		let eph_file: PathWrapper = "./provision_works.eph.key".into();
		let manifest_file: PathWrapper = "./provision_works.manifest".into();

		let Setup { quorum_pair, eph_pair, threshold, mut state, approvals } =
			setup(&eph_file, &quorum_file, &manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.to_master_seed();
		let encrypted_shares: Vec<_> =
			shares_generate(quorum_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(false));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		let boot_eph_key = std::fs::read(&*eph_file).unwrap();

		// 6) For shard K, call provision, make sure returns true and writes
		// quorum key as a ready only file
		let share = &encrypted_shares[threshold];
		let approval = approvals[threshold].clone();
		assert_eq!(provision(share, approval, &mut state), Ok(true));
		let quorum_key = std::fs::read(&*quorum_file).unwrap();

		assert_eq!(quorum_key, quorum_pair.to_master_seed_hex());

		// Make sure the EK is persisted
		assert!(Path::new(&*eph_file).exists());

		// Make sure the EK rotation happened, post-boot
		let new_eph_key = std::fs::read(&*eph_file).unwrap();
		assert_ne!(new_eph_key, boot_eph_key);

		// The share set approvals were recorded in the manifest envelope
		assert_eq!(
			state
				.handles
				.get_manifest_envelope()
				.unwrap()
				.share_set_approvals
				.len(),
			threshold
		);
	}

	#[test]
	fn provision_rejects_the_wrong_key() {
		let eph_file: PathWrapper =
			"./provision_rejects_the_wrong_key.eph.key".into();
		let quorum_file: PathWrapper =
			"./provision_rejects_the_wrong_key.quorum.key".into();
		let manifest_file: PathWrapper =
			"./provision_rejects_the_wrong_key.manifest".into();

		let Setup { eph_pair, threshold, mut state, approvals, .. } =
			setup(&eph_file, &quorum_file, &manifest_file);

		// 4) Create shards of a RANDOM KEY and encrypt them to eph key
		let random_key =
			P256Pair::generate().unwrap().to_master_seed().to_vec();
		let encrypted_shares: Vec<_> =
			shares_generate(&random_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(false));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) Add Kth shard of the random key
		let share = &encrypted_shares[threshold];
		let approval = approvals[threshold].clone();
		assert_eq!(
			provision(share, approval, &mut state),
			Err(ProtocolError::ReconstructionErrorIncorrectPubKey)
		);
		assert!(!Path::new(&*quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_if_a_shard_is_invalid() {
		let eph_file: PathWrapper =
			"./provision_rejects_if_a_shard_is_invalid.eph.key".into();
		let quorum_file: PathWrapper =
			"./provision_rejects_if_a_shard_is_invalid.quorum.key".into();
		let manifest_file: PathWrapper =
			"./provision_rejects_if_a_shard_is_invalid.manifest".into();
		let Setup { quorum_pair, eph_pair, threshold, mut state, approvals } =
			setup(&eph_file, &quorum_file, &manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.to_master_seed();

		let encrypted_shares: Vec<_> =
			shares_generate(quorum_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(false));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) Add a bogus shard as the Kth shard
		let bogus_share = &[69u8; 33];
		let encrypted_bogus_share =
			eph_pair.public_key().encrypt(bogus_share).unwrap();
		let approval = approvals[threshold].clone();
		assert_eq!(
			provision(&encrypted_bogus_share, approval, &mut state),
			Err(ProtocolError::ReconstructionErrorIncorrectPubKey)
		);
		assert!(!Path::new(&*quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provisions_rejects_if_an_approval_is_invalid() {
		let eph_file: PathWrapper =
			"./provisions_rejects_if_an_approval_is_invalid.eph.key".into();
		let quorum_file: PathWrapper =
			"./provisions_rejects_if_an_approval_is_invalid.quorum.key".into();
		let manifest_file: PathWrapper =
			"./provisions_rejects_if_an_approval_is_invalid.manifest".into();

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
		} = setup(&eph_file, &quorum_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(quorum_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let share = encrypted_shares.remove(0);
		let mut approval = approvals.remove(0);
		approval.signature =
			b"ffffffffffffffffffffffffffffffffffffffffffffff".to_vec();
		assert!(matches!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::CouldNotVerifyApproval { .. }
		));
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_if_approval_is_not_from_share_set_member() {
		let eph_file: PathWrapper =
			"./provision_rejects_if_approval_is_not_from_share_set_member.eph.key".into();
		let quorum_file: PathWrapper =
			"./provision_rejects_if_approval_is_not_from_share_set_member.quorum.key".into();
		let manifest_file: PathWrapper =
			"./provision_rejects_if_approval_is_not_from_share_set_member.manifest".into();

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
		} = setup(&eph_file, &quorum_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(quorum_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let manifest = state.handles.get_manifest_envelope().unwrap().manifest;
		let mut approval = approvals.remove(0);
		let pair = P256Pair::generate().unwrap();

		// Change the member so that are not recognized as part of the set
		approval.member.pub_key = pair.public_key().to_bytes();
		approval.signature = pair.sign(&manifest.qos_hash()).unwrap();

		let share = encrypted_shares.remove(0);
		assert!(matches!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::NotShareSetMember { .. }
		));
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature(
	) {
		let eph_file: PathWrapper =
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.eph.key".into();
		let quorum_file: PathWrapper =
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.quorum.key".into();
		let manifest_file: PathWrapper =
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.manifest".into();

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
		} = setup(&eph_file, &quorum_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(quorum_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let mut approval = approvals.remove(0);
		let pair = P256Pair::generate().unwrap();

		// Change the member so that are not recognized as part of the set
		approval.member.pub_key = pair.public_key().to_bytes();
		// DO NOT update the approval signature, so it doesn't match the pub key

		let share = encrypted_shares.remove(0);
		// we get an invalid signature error (not an error that they are not
		// part of the set)
		assert!(matches!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::CouldNotVerifyApproval { .. }
		));
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}
}
