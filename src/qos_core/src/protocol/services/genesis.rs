//! Genesis boot logic and types.

use std::{fmt, iter::zip};

use qos_crypto::sha_256;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{
	attestor::types::{NsmRequest, NsmResponse},
	boot::QuorumMember,
	Hash256, ProtocolError, ProtocolState, QosHash,
};

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

#[derive(PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
struct MemberShard {
	// TODO: is this taking up too much unnecessary space?
	/// Member of the Setup Set.
	member: QuorumMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	shard: Vec<u8>,
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
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RecoveredPermutation(Vec<MemberShard>);

/// Genesis output per Setup Member.
#[derive(
	PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct GenesisMemberOutput {
	/// The Quorum Member whom's Setup Key was used.
	pub share_set_member: QuorumMember,
	/// Quorum Key Share encrypted to the `setup_member`'s Personal Key.
	pub encrypted_quorum_key_share: Vec<u8>,
	/// Sha256 hash of the plaintext quorum key share. Used by the share set
	/// member to verify they correctly decrypted the share.
	pub share_hash: Hash256,
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
#[derive(PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
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
}

impl fmt::Debug for GenesisOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GenesisOutput")
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.field("threshold", &self.threshold)
			.field("member_outputs", &self.member_outputs)
			.field("recovery_permutations", &self.recovery_permutations)
			.finish()
	}
}

// TODO: Recovery logic!
// How many permutations of `threshold` keys should we use
// to reconstruct the original Quorum Key?
//
// TODO: Disaster recovery logic!
// Maybe we can just accept 2 set configs, and one is the recovery set?``
pub(in crate::protocol) fn boot_genesis(
	state: &mut ProtocolState,
	genesis_set: &GenesisSet,
) -> Result<(GenesisOutput, NsmResponse), ProtocolError> {
	// TODO: Entropy!
	let quorum_pair = P256Pair::generate()?;

	let shares = qos_crypto::shamir::shares_generate(
		&quorum_pair.to_master_seed()[..],
		genesis_set.members.len(),
		genesis_set.threshold as usize,
	);

	let member_outputs: Result<Vec<_>, _> =
		zip(shares, genesis_set.members.iter().cloned())
			.map(|(share, share_set_member)| -> Result<GenesisMemberOutput, ProtocolError>{
				// 1) encrypt the share to quorum key
				let personal_pub = P256Public::from_bytes(&share_set_member.pub_key)?;
				let encrypted_quorum_key_share =
					personal_pub.encrypt(&share)?;

				Ok(GenesisMemberOutput {
					share_set_member,
					encrypted_quorum_key_share,
					share_hash: sha_256(&share),
				})
			})
			.collect();

	let genesis_output = GenesisOutput {
		member_outputs: member_outputs?,
		quorum_key: quorum_pair.public_key().to_bytes(),
		threshold: genesis_set.threshold,
		// TODO: generate N choose K recovery permutations
		recovery_permutations: vec![],
	};

	let nsm_response = {
		let request = NsmRequest::Attestation {
			user_data: Some(genesis_output.qos_hash().to_vec()),
			nonce: None,
			public_key: None,
		};
		let fd = state.attestor.nsm_init();

		state.attestor.nsm_process_request(fd, request)
	};

	Ok((genesis_output, nsm_response))
}

#[cfg(test)]
mod test {
	use qos_p256::MASTER_SEED_LEN;

	use super::*;
	use crate::{
		handles::Handles, io::SocketAddress, protocol::attestor::mock::MockNsm,
	};

	#[test]
	fn boot_genesis_works() {
		let handles = Handles::new(
			"EPH".to_string(),
			"QUO".to_string(),
			"MAN".to_string(),
			"PIV".to_string(),
		);
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			handles.clone(),
			SocketAddress::new_unix("./never.sock"),
		);
		let member1_pair = P256Pair::generate().unwrap();
		let member2_pair = P256Pair::generate().unwrap();
		let member3_pair = P256Pair::generate().unwrap();

		let genesis_members = vec![
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

		let member_pairs = vec![member1_pair, member2_pair, member3_pair];

		let threshold = 2;
		let genesis_set = GenesisSet { members: genesis_members, threshold };

		let (output, _nsm_response) =
			boot_genesis(&mut protocol_state, &genesis_set).unwrap();
		let zipped = std::iter::zip(output.member_outputs, member_pairs);
		let shares: Vec<Vec<u8>> = zipped
			.map(|(output, pair)| {
				let decrypted_share =
					&pair.decrypt(&output.encrypted_quorum_key_share).unwrap();

				assert_eq!(sha_256(decrypted_share), output.share_hash);

				decrypted_share.clone()
			})
			.collect();

		let reconstructed: [u8; MASTER_SEED_LEN] =
			qos_crypto::shamir::shares_reconstruct(
				&shares[0..threshold as usize],
			)
			.try_into()
			.unwrap();
		let reconstructed_quorum_key =
			P256Pair::from_master_seed(&reconstructed).unwrap();

		let quorum_public_key =
			P256Public::from_bytes(&output.quorum_key).unwrap();
		assert_eq!(
			reconstructed_quorum_key.public_key().to_bytes(),
			quorum_public_key.to_bytes()
		);

		// Sanity check
		assert!(!handles.quorum_key_exists());
		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
	}
}
