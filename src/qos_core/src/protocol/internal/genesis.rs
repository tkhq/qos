//! Internal genesis data types.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::QuorumMember;

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(
	PartialEq, Debug, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct GenesisSet {
	/// Share Set Member's who's production key will be used to encrypt Genesis
	/// flow outputs.
	pub members: Vec<QuorumMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	pub threshold: u32,
}

#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub(crate) struct MemberShard {
	/// Member of the Setup Set.
	pub member: QuorumMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	pub shard: Vec<u8>,
}

impl fmt::Debug for MemberShard {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MemberShard")
			.field("member", &self.member)
			.field("shard", &qos_hex::encode(&self.shard))
			.finish()
	}
}

/// A set of member shards used to successfully recover the quorum key during
/// the genesis ceremony.
#[derive(
	PartialEq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub struct RecoveredPermutation(pub(crate) Vec<MemberShard>);

/// Genesis output per Setup Member.
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct GenesisMemberOutput {
	/// The Quorum Member whom's Setup Key was used.
	pub share_set_member: QuorumMember,
	/// Quorum Key Share encrypted to the `setup_member`'s Personal Key.
	#[serde(with = "qos_hex::serde")]
	pub encrypted_quorum_key_share: Vec<u8>,
	/// Sha512 hash of the plaintext quorum key share. Used by the share set
	/// member to verify they correctly decrypted the share.
	#[serde(with = "qos_hex::serde")]
	pub share_hash: [u8; 64],
}

impl fmt::Debug for GenesisMemberOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GenesisMemberOutput")
			.field("share_set_member", &self.share_set_member)
			.field(
				"encrypted_quorum_key_share",
				&qos_hex::encode(&self.encrypted_quorum_key_share),
			)
			.field("share_hash", &qos_hex::encode(&self.share_hash))
			.finish()
	}
}

/// Output from running Genesis Boot. Should contain all information relevant to
/// how the quorum shares where created.
#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub struct GenesisOutput {
	/// Public Quorum Key, DER encoded.
	pub quorum_key: Vec<u8>,
	/// Quorum Member specific outputs from the genesis ceremony.
	pub member_outputs: Vec<GenesisMemberOutput>,
	/// All successfully `RecoveredPermutation`s completed during the genesis
	/// process.
	pub recovery_permutations: Vec<RecoveredPermutation>,
	/// The threshold, K, used to generate the shards.
	pub threshold: u32,
	/// The quorum key encrypted to the DR key. None if no DR Key was provided
	pub dr_key_wrapped_quorum_key: Option<Vec<u8>>,
	/// Hash of the quorum key secret
	#[serde(with = "qos_hex::serde")]
	pub quorum_key_hash: [u8; 64],
	/// Test message encrypted to the quorum public key.
	pub test_message_ciphertext: Vec<u8>,
	/// Signature over the test message by the quorum key.
	pub test_message_signature: Vec<u8>,
	/// The message that was used to generate [`Self::test_message_signature`]
	/// and [`Self::test_message_ciphertext`]
	pub test_message: Vec<u8>,
}

impl fmt::Debug for GenesisOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GenesisOutput")
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.field("threshold", &self.threshold)
			.field("member_outputs", &self.member_outputs)
			.field("recovery_permutations", &self.recovery_permutations)
			.finish_non_exhaustive()
	}
}
