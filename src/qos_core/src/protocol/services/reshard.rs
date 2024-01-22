//! Quorum Key Resharding logic and types.

use core::iter::zip;
use std::collections::{HashMap, HashSet};

use qos_crypto::sha_512;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};

use super::provision::SecretBuilder;
use crate::protocol::{
	services::{
		attestation,
		boot::{Approval, NitroConfig, ShareSet},
		genesis::GenesisMemberOutput,
	},
	ProtocolError, ProtocolState, QosHash,
};

/// A share and the quorum key it is for.
#[derive(
	Debug,
	PartialEq,
	Eq,
	Clone,
	PartialOrd,
	Hash,
	Ord,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct ReshardProvisionShare {
	/// Share, encrypted to the ephemeral key
	#[serde(with = "qos_hex::serde")]
	pub share: Vec<u8>,
	/// Public key the share targets
	#[serde(with = "qos_hex::serde")]
	pub pub_key: Vec<u8>,
}

/// A single members input
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
pub struct ReshardProvisionInput {
	/// Approval over reshard input
	pub approval: Approval,
	/// Shares and the associated quorum keys
	pub shares: Vec<ReshardProvisionShare>,
}

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
	/// List of quorum public keys
	pub quorum_keys: Vec<Vec<u8>>,
	/// The set and threshold to shard the key.
	pub new_share_set: ShareSet,
	/// The set the key is currently sharded too.
	pub old_share_set: ShareSet,
	/// The expected configuration of the enclave. Useful to verify the
	/// attestation document against. We also want those posting shares to
	/// explicitly approve the version of QOS used.
	pub enclave: NitroConfig,
}

impl ReshardInput {
	fn deterministic(&mut self) {
		self.quorum_keys.sort();
	}

	fn validate(&mut self) -> Result<(), ProtocolError> {
		self.deterministic();

		let new_share_set_members: HashSet<_> = self
			.new_share_set
			.members
			.iter()
			.map(|m| m.pub_key.clone())
			.collect();

		if new_share_set_members.len() != self.new_share_set.members.len() {
			return Err(ProtocolError::DuplicateNewShareSetMember);
		}

		let quorum_pub_keys: HashSet<_> = self.quorum_keys.iter().collect();
		if quorum_pub_keys.len() != self.quorum_keys.len() {
			return Err(ProtocolError::DuplicateQuorumKeys);
		}

		Ok(())
	}

	/// Get a set of the quorum keys.
	#[must_use]
	pub fn quorum_keys(&self) -> HashSet<Vec<u8>> {
		self.quorum_keys.iter().cloned().collect()
	}
}

pub(crate) struct ReshardProvisioner {
	secret_builders: HashMap<Vec<u8>, SecretBuilder>,
	quorum_key_count: usize,
}

impl ReshardProvisioner {
	pub(in crate::protocol) fn new(quorum_key_count: usize) -> Self {
		Self { secret_builders: HashMap::new(), quorum_key_count }
	}

	pub(in crate::protocol) fn add_shares(
		&mut self,
		shares: Vec<ReshardProvisionShare>,
		eph_key: &P256Pair,
	) -> Result<(), ProtocolError> {
		if shares.len() != self.quorum_key_count {
			return Err(
				ProtocolError::ShareCountDoesNotMatchExpectedQuorumKeyCount,
			);
		}

		for ReshardProvisionShare { share, pub_key } in shares {
			let decrypted_share = eph_key
				.decrypt(&share)
				.map_err(|_| ProtocolError::ShareDecryptionFailed)?;

			let builder = self
				.secret_builders
				.entry(pub_key)
				.or_insert_with(SecretBuilder::new);
			builder.add_share(decrypted_share)?;
		}

		Ok(())
	}

	pub(in crate::protocol) fn share_count(
		&self,
	) -> Result<usize, ProtocolError> {
		Ok(self
			.secret_builders
			.values()
			.try_fold(None, |count, builder| {
				if let Some(current_count) = count {
					if current_count != builder.count() {
						return Err(
							ProtocolError::InternalDiffCountsForQuorumKeyShares,
						);
					}
					Ok(count)
				} else {
					Ok(Some(builder.count()))
				}
			})?
			.unwrap_or(0))
	}

	pub(in crate::protocol) fn build(
		&mut self,
	) -> Result<Vec<P256Pair>, ProtocolError> {
		self.secret_builders
			.drain()
			.map(|(public, builder)| {
				let master_seed: [u8; 32] = builder
					.build()?
					.try_into()
					.map_err(|_| ProtocolError::IncorrectSecretLen)?;

				let pair = P256Pair::from_master_seed(&master_seed)?;
				let public_key_bytes = pair.public_key().to_bytes();

				if public_key_bytes != public {
					return Err(
						ProtocolError::ReconstructionErrorIncorrectPubKey,
					);
				}

				Ok(pair)
			})
			.collect::<Result<Vec<P256Pair>, ProtocolError>>()
	}
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
	/// The new encrypted shards along with metadata about the share set member
	/// they where encrypted to.
	pub outputs: Vec<(Vec<u8>, Vec<GenesisMemberOutput>)>,
	/// The set the keys where sharded too.
	pub new_share_set: ShareSet,
}

pub(in crate::protocol) fn boot_reshard(
	state: &mut ProtocolState,
	mut reshard_input: ReshardInput,
) -> Result<NsmResponse, ProtocolError> {
	// 1. Validate reshard input
	reshard_input.validate()?;
	// 2. Initialize reshard provisioner
	state.reshard_provisioner =
		Some(ReshardProvisioner::new(reshard_input.quorum_keys.len()));
	// 3. Store reshard input in state
	state.reshard_input = Some(reshard_input);

	// 4. Generate an Ephemeral Key.
	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;

	attestation::reshard_attestation_doc(state)
}

pub(in crate::protocol) fn reshard_output(
	state: &mut ProtocolState,
) -> Result<ReshardOutput, ProtocolError> {
	state.reshard_output.clone().ok_or(ProtocolError::MissingReshardOutput)
}

pub(in crate::protocol) fn reshard_provision(
	input: ReshardProvisionInput,
	state: &mut ProtocolState,
) -> Result<bool, ProtocolError> {
	let reshard_input = state
		.reshard_input
		.as_ref()
		.ok_or(ProtocolError::MissingReshardInput)?
		.clone();

	input.approval.verify(&reshard_input.qos_hash())?;

	if !reshard_input.old_share_set.members.contains(&input.approval.member) {
		return Err(ProtocolError::NotShareSetMember);
	}

	let ephemeral_key = state.handles.get_ephemeral_key()?;
	state
		.get_mut_reshard_provisioner()?
		.add_shares(input.shares, &ephemeral_key)?;

	let quorum_threshold = reshard_input.old_share_set.threshold as usize;
	if state.get_mut_reshard_provisioner()?.share_count()? < quorum_threshold {
		// Nothing else to do if we don't have the threshold to reconstruct
		return Ok(false);
	}

	let quorum_key_pairs = state.get_mut_reshard_provisioner()?.build()?;
	let outputs = quorum_key_pairs
		.iter()
		.map(|pair| {
			let master_seed = pair.to_master_seed();
			let pub_key = pair.public_key().to_bytes();

			let shares = qos_crypto::shamir::shares_generate(
				&master_seed[..],
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

			Ok((pub_key, member_outputs))
		})
		.collect::<Result<Vec<_>, ProtocolError>>()?;

	state.reshard_output = Some(ReshardOutput {
		outputs,
		new_share_set: reshard_input.new_share_set,
	});

	Ok(true)
}

#[cfg(test)]
mod tests {
	use qos_crypto::{n_choose_k, shamir::shares_generate};
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{
		handles::Handles,
		io::SocketAddress,
		protocol::{services::boot::QuorumMember, ProtocolPhase, QosHash},
	};

	struct ReshardSetup {
		state: ProtocolState,
		new_members: Vec<(QuorumMember, P256Pair)>,
		eph_pair: P256Pair,
		/// Quorum pairs and associated shares, encrypted to the ephemeral key.
		provision_inputs: Vec<ReshardProvisionInput>,
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

		let quorum_pairs: Vec<_> = (0..4)
			.map(|_| {
				let pair = P256Pair::generate().unwrap();

				let encrypted_shares: Vec<_> = shares_generate(
					&pair.to_master_seed()[..],
					4,
					3, // old share set threshold
				)
				.iter()
				.map(|s| eph_pair.public_key().encrypt(s).unwrap())
				.collect();

				(pair, encrypted_shares)
			})
			.collect();
		let quorum_keys: Vec<_> =
			quorum_pairs.iter().map(|p| p.0.public_key().to_bytes()).collect();

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
			quorum_keys,
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

		let provision_inputs: Vec<_> = old_members
			.into_iter()
			.enumerate()
			.map(|(idx, (member, pair))| {
				let shares = quorum_pairs
					.iter()
					.map(|(pair, shares)| ReshardProvisionShare {
						share: shares[idx].clone(),
						pub_key: pair.public_key().to_bytes(),
					})
					.collect();
				let approval = Approval {
					member,
					signature: pair.sign(&reshard_input.qos_hash()).unwrap(),
				};

				ReshardProvisionInput { approval, shares }
			})
			.collect();

		let mut state = ProtocolState::new(
			Box::new(MockNsm),
			handles,
			SocketAddress::new_unix("./never.sock"),
			None,
		);
		state.reshard_input = Some(reshard_input);
		state.reshard_provisioner =
			Some(ReshardProvisioner::new(quorum_pairs.len()));
		state.transition(ProtocolPhase::ReshardWaitingForQuorumShards).unwrap();

		ReshardSetup { state, new_members, eph_pair, provision_inputs }
	}

	#[test]
	fn reshard_provision_works() {
		let eph_file: PathWrapper =
			"/tmp/reshard_provision_works.eph.key".into();

		let ReshardSetup { mut state, new_members, provision_inputs, .. } =
			reshard_setup(&eph_file);

		// We expect reshard_provision to return Ok(false) for the first
		// 2
		for i in provision_inputs.iter().take(2) {
			assert_eq!(reshard_provision(i.clone(), &mut state), Ok(false));
		}

		// And then return Ok(true) for the 3rd share to signal it has been
		// reconstructed
		assert_eq!(
			reshard_provision(provision_inputs[2].clone(), &mut state),
			Ok(true)
		);

		let reshard_output = state.reshard_output.clone().unwrap();
		let reshard_input = state.reshard_input.clone().unwrap();
		assert_eq!(reshard_output.new_share_set, reshard_input.new_share_set);

		for (quorum_pub, member_outputs) in reshard_output.outputs {
			// Check that decrypted shares match hash
			let mut decrypted_shares = vec![];
			for (member_out, (member, pair)) in
				zip(member_outputs, new_members.clone())
			// TODO: check that these make sense
			{
				let share = pair
					.decrypt(&member_out.encrypted_quorum_key_share)
					.unwrap();
				assert_eq!(
					&member_out.share_hash,
					&qos_crypto::sha_512(&share),
				);
				assert_eq!(member_out.share_set_member, member);

				decrypted_shares.push(share);
			}

			// Now make sure all combos of shares work
			for combo in n_choose_k::combinations(
				&decrypted_shares,
				reshard_output.new_share_set.threshold as usize,
			) {
				let secret: [u8; 32] =
					qos_crypto::shamir::shares_reconstruct(&combo)
						.try_into()
						.unwrap();
				let quorum_key = P256Pair::from_master_seed(&secret).unwrap();
				assert_eq!(quorum_pub, quorum_key.public_key().to_bytes());
			}
		}
	}

	#[test]
	fn reshard_provision_rejects_wrong_reconstructed_key() {
		let eph_file: PathWrapper =
			"/tmp/reshard_provision_rejects_wrong_reconstructed_key.eph.key"
				.into();

		let ReshardSetup { eph_pair, mut state, mut provision_inputs, .. } =
			reshard_setup(&eph_file);

		let reshard_input = state.reshard_input.clone().unwrap();
		let random_pair = P256Pair::generate().unwrap();
		let encrypted_shares: Vec<_> = shares_generate(
			random_pair.to_master_seed(),
			4,
			reshard_input.new_share_set.threshold as usize,
		)
		.iter()
		.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
		.collect();

		for (i, user_input) in provision_inputs.iter_mut().enumerate() {
			// loop through each of the users input and modify their first share
			// to be for a different public key
			user_input.shares[0].share = encrypted_shares[i].clone();
		}

		// We expect reshard_provision to return Ok(false) for the first
		// 2
		for i in provision_inputs.iter().take(2) {
			assert_eq!(reshard_provision(i.clone(), &mut state), Ok(false));
		}

		// And then return an error for the 3rd share to signal it has been
		// reconstructed
		assert_eq!(
			reshard_provision(provision_inputs[2].clone(), &mut state),
			Err(ProtocolError::ReconstructionErrorIncorrectPubKey)
		);
	}

	#[test]
	fn reshard_provision_rejects_bad_approval_signature() {
		let eph_file: PathWrapper =
			"/tmp/reshard_provision_rejects_bad_approval_signature.eph.key"
				.into();

		let ReshardSetup {
			mut state, mut provision_inputs, new_members, ..
		} = reshard_setup(&eph_file);

		// give the third approval a random signature
		provision_inputs[2].approval.signature =
			new_members[2].1.sign(&[42; 32]).unwrap();

		// We expect reshard_provision to return Ok(false) for the first
		// 2
		for i in provision_inputs.iter().take(2) {
			assert_eq!(reshard_provision(i.clone(), &mut state), Ok(false));
		}

		// And then return an error for the 3rd share to signal it has been
		// reconstructed
		assert_eq!(
			reshard_provision(provision_inputs[2].clone(), &mut state),
			Err(ProtocolError::CouldNotVerifyApproval)
		);
	}

	#[test]
	fn reshard_provision_rejects_approval_not_from_member() {
		let eph_file: PathWrapper =
			"/tmp/reshard_provision_rejects_approval_not_from_member.eph.key"
				.into();

		let ReshardSetup {
			eph_pair,
			mut state,
			mut provision_inputs,
			new_members,
			..
		} = reshard_setup(&eph_file);

		let reshard_input = state.reshard_input.clone().unwrap();
		let random_pair = P256Pair::generate().unwrap();
		let _encrypted_shares: Vec<_> = shares_generate(
			random_pair.to_master_seed(),
			4,
			reshard_input.new_share_set.threshold as usize,
		)
		.iter()
		.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
		.collect();

		// the old and new members are unique. We only expect approvals from the
		// old members. So if a new members approval comes in, we don't accept
		// it.
		provision_inputs[2].approval.signature =
			new_members[0].1.sign(&reshard_input.qos_hash()).unwrap();
		provision_inputs[2].approval.member = new_members[0].0.clone();

		// We expect reshard_provision to return Ok(false) for the first
		// 2
		for i in provision_inputs.iter().take(2) {
			assert_eq!(reshard_provision(i.clone(), &mut state), Ok(false));
		}

		// And then return an error for the 3rd share to signal it has been
		// reconstructed
		assert_eq!(
			reshard_provision(provision_inputs[2].clone(), &mut state),
			Err(ProtocolError::NotShareSetMember)
		);
	}

	#[test]
	fn boot_reshard_works() {
		let eph_file: PathWrapper = "/tmp/boot_reshard_works.eph.key".into();

		let handles = Handles::new(
			eph_file.to_string(),
			"/tmp/qos-quorum".to_string(),
			"/tmp/qos-manifest".to_string(),
			"/tmp/qos-pivot".to_string(),
		);
		let mut state = ProtocolState::new(
			Box::new(MockNsm),
			handles,
			SocketAddress::new_unix("./never.sock"),
			None,
		);

		let reshard_input = ReshardInput {
			quorum_keys: vec![vec![1; 65], vec![2; 65]],
			new_share_set: ShareSet { threshold: 2, members: vec![] },
			old_share_set: ShareSet { threshold: 3, members: vec![] },
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate:
					b"super swag root cert your friends told you about".to_vec(),
				qos_commit: "a commit ref".to_string(),
			},
		};

		assert!(boot_reshard(&mut state, reshard_input.clone(),).is_ok());

		assert_eq!(state.reshard_input, Some(reshard_input));
		assert_eq!(state.reshard_output, None);
		assert!(state.handles.get_ephemeral_key().is_ok());
	}
}
