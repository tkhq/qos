//! Genesis boot logic and types.

use std::iter::zip;

use qos_crypto::{RsaPair, RsaPub, sha_256};

use crate::protocol::{
	attestor::types::{NsmRequest, NsmResponse},
	boot::QuorumMember,
	ProtocolError, ProtocolState, QosHash, Hash256
};

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct GenesisSet {
	/// Share Set Member's who's production key will be used to encrypt Genesis
	/// flow outputs.
	pub members: Vec<QuorumMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	pub threshold: u32,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
struct MemberShard {
	// TODO: is this taking up too much unnecessary space?
	/// Member of the Setup Set.
	member: QuorumMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	shard: Vec<u8>,
}

/// A set of member shards used to successfully recover the quorum key during the
/// genesis ceremony.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RecoveredPermutation(Vec<MemberShard>);

/// Genesis output per Setup Member.
#[derive(
	PartialEq, Eq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
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

/// Output from running Genesis Boot. Should contain all information relevant to
/// how the quorum shares where created.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
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
	let quorum_pair = RsaPair::generate()?;

	let shares = qos_crypto::shamir::shares_generate(
		&quorum_pair.private_key_to_der()?,
		genesis_set.members.len(),
		genesis_set.threshold as usize,
	);

	let member_outputs: Result<Vec<_>, _> =
		zip(shares, genesis_set.members.iter().cloned())
			.map(|(share, share_set_member)| -> Result<GenesisMemberOutput, ProtocolError>{
				// 1) encrypt the share to quorum key
				let personal_pub = RsaPub::from_der(&share_set_member.pub_key)?;
				let encrypted_quorum_key_share =
					personal_pub.envelope_encrypt(&share)?;

				Ok(GenesisMemberOutput {
					share_set_member,
					encrypted_quorum_key_share,
					share_hash: sha_256(&share),
				})
			})
			.collect();

	let genesis_output = GenesisOutput {
		member_outputs: member_outputs?,
		quorum_key: quorum_pair.public_key_to_der()?,
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
		let member1_pair = RsaPair::generate().unwrap();
		let member2_pair = RsaPair::generate().unwrap();
		let member3_pair = RsaPair::generate().unwrap();

		let genesis_members = vec![
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

		let member_pairs = vec![member1_pair, member2_pair, member3_pair];

		let threshold = 2;
		let genesis_set = GenesisSet { members: genesis_members, threshold };

		let (output, _nsm_response) =
			boot_genesis(&mut protocol_state, &genesis_set).unwrap();
		let zipped = std::iter::zip(output.member_outputs, member_pairs);
		let shares: Vec<Vec<u8>> = zipped
			.map(|(output, pair)| {
				let decrypted_share = &pair
						.envelope_decrypt(&output.encrypted_quorum_key_share)
						.unwrap();

				assert_eq!(
					sha_256(decrypted_share),
					output.share_hash
				);

				decrypted_share.clone()
			})
			.collect();

		let reconstructed = qos_crypto::shamir::shares_reconstruct(
			&shares[0..threshold as usize],
		);
		let reconstructed_quorum_key =
			RsaPair::from_der(&reconstructed).unwrap();

		let quorum_public_key = RsaPub::from_der(&output.quorum_key).unwrap();
		assert_eq!(reconstructed_quorum_key.public_key(), &quorum_public_key);

		// Sanity check
		assert!(!handles.quorum_key_exists());
		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
	}
}
