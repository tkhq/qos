use core::iter::zip;

use qos_crypto::sha_512;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	services::boot::MemberPubKey, ProtocolError, ProtocolState,
};

/// The set of share keys that can post shares.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ShardSet {
	/// The threshold, K, of signatures necessary to have quorum.
	pub threshold: u32,
	/// Public keys of members composing the set. The length of this, N, must
	/// be gte to the `threshold`, K.
	pub members: Vec<MemberPubKey>,
}

#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct ShardSetMemberOutput {
	/// Public key of the member.
	pub member_public_key: MemberPubKey,
	/// Quorum Key Share encrypted to the member's public key.
	pub encrypted_quorum_key_share: Vec<u8>,
	/// Sha512 hash of the plaintext quorum key share. Used by the shard set
	/// member to verify they correctly decrypted the share.
	pub share_hash: Vec<u8>,
}

#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct ShardConfig {
	shard_set: ShardSet,
	quorum_key: Vec<u8>,
}

#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct ShardOutput {
	/// Public Quorum Key
	pub quorum_key: Vec<u8>,
	/// The threshold, K, used to generate the shards.
	pub threshold: u32,
	/// The new shares for the given members
	pub member_outputs: Vec<ShardSetMemberOutput>,
}

fn boot_shard(
	state: &mut ProtocolState,
	shard_set: ShardSet,
	quorum_key: Vec<u8>,
) -> Result<NsmResponse, ProtocolError> {
	let shard_config = ShardConfig { quorum_key, shard_set };

	// Generate an Ephemeral Key.
	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;

	// Make an attestation request, placing the shard config digest in the
	// `user_data` field and the Ephemeral Key public key in the `public_key`
	// field.
	let nsm_response = attestation::get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_key.public_key().to_bytes(),
		shard_config.qos_hash().to_vec(),
	);

	// Persist the shard config
	state.shard_config = Some(shard_config);

	Ok(nsm_response)
}

// TODO(zeke): route to get the shard output
// TODO(zeke): add a quorum key signature to shard output

fn shard(
	state: &mut ProtocolState,
	quorum_pair: P256Pair,
) -> Result<(), ProtocolError> {
	let shard_config =
		state.shard_config.as_ref().ok_or(ProtocolError::NotShardBooted)?;

	let master_seed = &quorum_pair.to_master_seed()[..];

	let shares = qos_crypto::shamir::shares_generate(
		master_seed,
		shard_config.shard_set.members.len(),
		shard_config.shard_set.threshold as usize,
	);

	let member_outputs: Result<Vec<ShardSetMemberOutput>, ProtocolError> =
		zip(shares, shard_config.shard_set.members.iter().cloned())
			.map(|(share, member_public_key)| {
				let member_pub =
					P256Public::from_bytes(&member_public_key.pub_key)?;
				let encrypted_quorum_key_share = member_pub.encrypt(&share)?;

				Ok(ShardSetMemberOutput {
					member_public_key,
					encrypted_quorum_key_share,
					share_hash: sha_512(&share).to_vec(),
				})
			})
			.collect();

	// TODO: we should sign the outputs with the quorum key
	let shard_output = ShardOutput {
		quorum_key: quorum_pair.public_key().to_bytes(),
		threshold: shard_config.shard_set.threshold,
		member_outputs: member_outputs?,
	};

	state.shard_output = Some(shard_output);

	Ok(())
}

pub(in crate::protocol) fn shard_provision(
	state: &mut ProtocolState,
	encrypted_share: &[u8],
) -> Result<bool, ProtocolError> {
	let shard_config =
		state.shard_config.as_ref().ok_or(ProtocolError::NotShardBooted)?;
	let ephemeral_key = state.handles.get_ephemeral_key()?;

	let share = ephemeral_key
		.decrypt(encrypted_share)
		.map_err(|_| ProtocolError::DecryptionFailed)?;

	state.provisioner.add_share(share)?;

	let quorum_threshold = shard_config.shard_set.threshold as usize;
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

	if public_key_bytes != shard_config.quorum_key {
		return Err(ProtocolError::WrongQuorumKey);
	}

	shard(state, pair)?;

	Ok(true)
}
