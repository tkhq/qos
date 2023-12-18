//! Quorum Key Resharding logic and types.

use core::iter::zip;

use qos_crypto::sha_512;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	services::{
		attestation,
		boot::{Approval, NitroConfig, ShareSet},
		genesis::GenesisMemberOutput,
	},
	ProtocolError, ProtocolState, QosHash,
};

/// The parameters for setting up the reshard service.
#[derive(
	Debug,
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ReshardInput {
	/// The quorum public key to reshard
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
	/// The set and threshold to shard the key.
	pub new_share_set: ShareSet,
	/// The set the key is currently sharded too.
	pub old_share_set: ShareSet,
	/// The expected configuration of the enclave. Useful to verify the
	/// attestation document against. TODO: this isn't strictly neccesary.
	pub enclave: NitroConfig,
}

/// The output of performing a quorum key reshard.
#[derive(
	Debug,
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ReshardOutput {
	/// The quorum key tjhat was resharded
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
	/// The new encrypted shards along with metadata about the share set member
	/// they where encrypted to.
	pub member_outputs: Vec<GenesisMemberOutput>,
	/// The set the key was sharded too.
	pub new_share_set: ShareSet,
}

pub(in crate::protocol) fn boot_reshard(
	state: &mut ProtocolState,
	reshard_input: ReshardInput,
) -> Result<NsmResponse, ProtocolError> {
	// 1. Store reshard input in state
	state.reshard_input = Some(reshard_input);

	// 2. Generate an Ephemeral Key.
	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;

	attestation::reshard_attestation_doc(state)
}

pub(in crate::protocol) fn reshard_provision(
	encrypted_share: &[u8],
	approval: &Approval,
	state: &mut ProtocolState,
) -> Result<bool, ProtocolError> {
	let reshard_input = state
		.reshard_input
		.as_ref()
		.ok_or(ProtocolError::MissingReshardInput)?
		.clone();

	approval.verify(&encrypted_share.qos_hash())?;

	if !reshard_input.old_share_set.members.contains(&approval.member) {
		return Err(ProtocolError::NotShareSetMember);
	}

	let ephemeral_key = state.handles.get_ephemeral_key()?;

	let share = ephemeral_key
		.decrypt(encrypted_share)
		.map_err(|_| ProtocolError::DecryptionFailed)?;

	state.provisioner.add_share(share)?;

	let quorum_threshold = reshard_input.old_share_set.threshold as usize;
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

	if public_key_bytes != reshard_input.quorum_key {
		return Err(ProtocolError::ReconstructionErrorIncorrectPubKey);
	}

	let shares = qos_crypto::shamir::shares_generate(
		&master_seed,
		reshard_input.new_share_set.members.len(),
		reshard_input.new_share_set.threshold as usize,
	);

	// Now, lets create the new shards
	let member_outputs =
		zip(shares, reshard_input.new_share_set.members.iter().cloned())
			.map(|(share, share_set_member)| -> Result<GenesisMemberOutput, ProtocolError> {
				// 1) encrypt the share to quorum key
				let personal_pub = P256Public::from_bytes(&share_set_member.pub_key)?;
				let encrypted_quorum_key_share = personal_pub.encrypt(&share)?;

				Ok(GenesisMemberOutput {
					share_set_member,
					encrypted_quorum_key_share,
					share_hash: sha_512(&share),
				})
			})
			.collect::<Result<Vec<_>, _>>()?;

	state.reshard_output = Some(ReshardOutput {
		quorum_key: public_key_bytes,
		member_outputs,
		new_share_set: reshard_input.new_share_set,
	});

	Ok(true)
}

#[cfg(test)]
mod tests {
	use qos_crypto::shamir::shares_generate;
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{
		handles::Handles,
		io::SocketAddress,
		protocol::{
			n_choose_k, services::boot::QuorumMember, ProtocolPhase, QosHash,
		},
	};

	struct ReshardSetup {
		state: ProtocolState,
		new_members: Vec<(QuorumMember, P256Pair)>,
		old_members: Vec<(QuorumMember, P256Pair)>,
		eph_pair: P256Pair,
		quorum_pair: P256Pair,
		approvals: Vec<Approval>,
	}

	fn reshard_setup(eph_file: &str) -> ReshardSetup {
		let handles = Handles::new(
			eph_file.to_string(),
			"/tmp/qos-quorum".to_string(),
			"/tmp/qos-manifest".to_string(),
			"/tmp/qos-pivot".to_string(),
		);
		let eph_pair = P256Pair::generate().unwrap();
		handles.put_ephemeral_key(&eph_pair).unwrap();

		let quorum_pair = P256Pair::generate().unwrap();

		let old_members: Vec<_> = (0..4)
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

		let new_members: Vec<_> = (0..4)
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

		let reshard_input = ReshardInput {
			quorum_key: quorum_pair.public_key().to_bytes(),
			new_share_set: ShareSet {
				threshold: 2,
				members: new_members.iter().map(|(qm, _)| qm.clone()).collect(),
			},
			old_share_set: ShareSet {
				threshold: 3,
				members: old_members.iter().map(|(qm, _)| qm.clone()).collect(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"bezo's son, a dad of certs".to_vec(),
				qos_commit: "super chill commit ref you can bro down with"
					.to_string(),
			},
		};

		let approvals: Vec<_> = old_members
			.clone()
			.into_iter()
			.map(|(member, pair)| {
				let approval = Approval {
					member,
					signature: pair.sign(&reshard_input.qos_hash()).unwrap(),
				};

				assert!(approval.verify(&reshard_input.qos_hash()).is_ok());

				approval
			})
			.collect();

		let mut state = ProtocolState::new(
			Box::new(MockNsm),
			handles,
			SocketAddress::new_unix("./never.sock"),
			None,
		);
		state.reshard_input = Some(reshard_input);
		state.transition(ProtocolPhase::ReshardWaitingForQuorumShards).unwrap();

		ReshardSetup {
			state,
			new_members,
			old_members,
			eph_pair,
			quorum_pair,
			approvals,
		}
	}

	#[test]
	fn reshard_provision_works() {
		let eph_file: PathWrapper = "./reshard_provision_works.eph.key".into();

		let ReshardSetup {
			quorum_pair,
			eph_pair,
			mut state,
			approvals,
			old_members: _,
			new_members,
		} = reshard_setup(&eph_file);

		let quorum_key = quorum_pair.to_master_seed();
		let encrypted_shares: Vec<_> = shares_generate(
			quorum_key,
			4,
			state.reshard_input.clone().unwrap().old_share_set.threshold
				as usize,
		)
		.iter()
		.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
		.collect();

		// We expect reshard_provision to return Ok(false) for the first
		// 2
		for i in 0..2 {
			assert_eq!(
				reshard_provision(
					&encrypted_shares[i],
					&approvals[i],
					&mut state
				),
				Ok(false)
			);
		}

		// And then return Ok(true) for the 3rd share to signal it has been
		// reconstructed
		assert_eq!(
			reshard_provision(&encrypted_shares[2], &approvals[2], &mut state),
			Ok(true)
		);

		let reshard_output = state.reshard_output.clone().unwrap();
		let reshard_input = state.reshard_input.clone().unwrap();
		assert_eq!(reshard_output.new_share_set, reshard_input.new_share_set);
		assert_eq!(reshard_output.quorum_key, reshard_input.quorum_key);

		// Check that decrypted shares match hash
		let mut decrypted_shares = vec![];
		for (member_out, (member, pair)) in
			zip(reshard_output.member_outputs, new_members)
		{
			let share =
				pair.decrypt(&member_out.encrypted_quorum_key_share).unwrap();
			assert_eq!(&member_out.share_hash, &qos_crypto::sha_512(&share),);
			assert_eq!(member_out.share_set_member, member);

			decrypted_shares.push(share);
		}

		// Now make sure all combos of shares work
		for combo in n_choose_k::combinations(
			&decrypted_shares,
			reshard_output.new_share_set.threshold as usize,
		) {
			let secret = qos_crypto::shamir::shares_reconstruct(&combo);
			assert_eq!(quorum_key.to_vec(), secret);
		}
	}

	#[test]
	fn reshard_provision_rejects_wrong_reconstructed_key() {}

	#[test]
	fn reshard_provision_rejects_bad_approval_signature() {}

	#[test]
	fn reshard_provision_rejects_approval_not_from_member() {}
}
