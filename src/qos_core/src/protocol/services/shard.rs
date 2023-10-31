use crate::protocol::services::boot::MemberPubKey;
use crate::protocol::ProtocolState;
use crate::protocol::ProtocolError;
use core::iter::zip;
use qos_p256::P256Public;
use qos_crypto::sha_512;

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
	pub share_hash: Vec<u8>
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

/// Shard the given quorum quorum key to the new a new `shard_set`.
///
/// # Arguments
///
/// * `state` - enclave's `ProtocolState`
/// * `shard_set` - the set to reshard the quorum key to
/// * `expected_quorum_key` - the public key of the expected quorum key
pub(crate) fn shard(
	state: &mut ProtocolState,
	shard_set: &ShardSet,
	expected_quorum_key: Vec<u8>,
) -> Result<ShardOutput, ProtocolError> {
	let quorum_pair = state.handles.get_quorum_key()?;
	if quorum_pair.public_key().to_bytes() != expected_quorum_key {
		return Err(ProtocolError::WrongQuorumKey)
	}

	let master_seed = &quorum_pair.to_master_seed()[..];

	let shares = qos_crypto::shamir::shares_generate(
		master_seed,
		shard_set.members.len(),
		shard_set.threshold as usize,
	);

	let member_outputs: Result<Vec<ShardSetMemberOutput>, ProtocolError>
		= zip(shares, shard_set.members.iter().cloned())
		.map(|(share, member_public_key)| {
			let member_pub = P256Public::from_bytes(&member_public_key.pub_key)?;
			let encrypted_quorum_key_share = member_pub.encrypt(&share)?;

			Ok(ShardSetMemberOutput {
				member_public_key,
				encrypted_quorum_key_share,
				share_hash: sha_512(&share).to_vec()
			})
		})
		.collect();

	Ok(
		ShardOutput {
			quorum_key: quorum_pair.public_key().to_bytes(),
			threshold: shard_set.threshold,
			member_outputs: member_outputs?,
		}
	)
}