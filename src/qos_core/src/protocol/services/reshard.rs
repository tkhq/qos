//! Quorum Key Resharding logic and types.

use qos_nsm::types::NsmResponse;
use qos_p256::P256Pair;

use crate::protocol::{
	services::{
		attestation,
		boot::{NitroConfig, ShareSet},
		genesis::GenesisMemberOutput,
	},
	ProtocolError, ProtocolState,
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
	pub new_shares_set: ShareSet,
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
	/// The message that was used to generate [`Self::test_message_signature`].
	#[serde(with = "qos_hex::serde")]
	pub test_message: Vec<u8>,
	/// `Self::quorum_key` signature over [`Self::test_message`].
	#[serde(with = "qos_hex::serde")]
	pub test_message_signature: Vec<u8>,
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
