//! Genesis boot logic and types.

use std::iter::zip;

use qos_crypto::{RsaPair, RsaPub};

use crate::protocol::{
	attestor::types::{NsmRequest, NsmResponse},
	ProtocolError, ProtocolState, QosHash,
};

/// Member of the [`SetupSet`].
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SetupMember {
	/// A unique UTF-8 encoded string to help Human participants to identify
	/// this member.
	pub alias: String,
	/// A DER encoded Setup Key that will be used by the Genesis flow to
	/// encrypt a Personal Key.
	pub pub_key: Vec<u8>,
}

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct GenesisSet {
	/// Quorum Member's whoms setup key will be used to encrypt Genesis flow
	/// outputs.
	pub members: Vec<SetupMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	pub threshold: u32,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
struct MemberShard {
	// TODO: is this taking up too much unnecessary space?
	/// Member of the Setup Set.
	member: SetupMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	shard: Vec<u8>,
}

/// A set of member shards used to succesfully recover the quorum key during the
/// genesis ceremony.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RecoveredPermutation(Vec<MemberShard>);

/// Genesis output per Setup Member.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct GenesisMemberOutput {
	/// The Quorum Member whom's Setup Key was used.
	pub setup_member: SetupMember,
	/// Quorum Key Share encrypted to the `setup_member`'s Personal Key.
	pub encrypted_quorum_key_share: Vec<u8>,
	/// Personal Key encrypted to the `setup_member`'s Setup Key.
	pub encrypted_personal_key: Vec<u8>,
}

/// Output from running Genesis Boot.
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

	let mut member_outputs = Vec::with_capacity(shares.len());
	let zipped = zip(shares, genesis_set.members.iter().cloned());
	for (share, setup_member) in zipped.clone() {
		// 1) generate Personal Key pair
		let personal_pair = RsaPair::generate()?;

		// 2) encrypt Personal Key to Setup Key
		let encrypted_personal_key = {
			let setup_key = RsaPub::from_der(&setup_member.pub_key)?;
			let personal_der = personal_pair.private_key_to_der()?;

			setup_key.envelope_encrypt(&personal_der)?
		};

		// 3) encrypt the Quorum Share to the Personal Key
		let encrypted_quorum_key_share =
			personal_pair.envelope_encrypt(&share)?;

		member_outputs.push(GenesisMemberOutput {
			setup_member,
			encrypted_quorum_key_share,
			encrypted_personal_key,
		});
	}

	let genesis_output = GenesisOutput {
		member_outputs,
		quorum_key: quorum_pair.public_key_to_der()?,
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
	use crate::protocol::attestor::mock::MockNsm;

	#[test]
	fn boot_genesis_works() {
		let mut protocol_state = ProtocolState::new(
			Box::new(MockNsm),
			"secret".to_string(),
			"pivot".to_string(),
			"ephemeral".to_string(),
		);
		let member1_pair = RsaPair::generate().unwrap();
		let member2_pair = RsaPair::generate().unwrap();
		let member3_pair = RsaPair::generate().unwrap();

		let genesis_members = vec![
			SetupMember {
				alias: "member1".to_string(),
				pub_key: member1_pair.public_key_to_der().unwrap(),
			},
			SetupMember {
				alias: "member2".to_string(),
				pub_key: member2_pair.public_key_to_der().unwrap(),
			},
			SetupMember {
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
				let personal_key = RsaPair::from_der(
					&pair
						.envelope_decrypt(&output.encrypted_personal_key)
						.unwrap(),
				)
				.unwrap();
				personal_key
					.envelope_decrypt(&output.encrypted_quorum_key_share)
					.unwrap()
			})
			.collect();

		let reconstructed = qos_crypto::shamir::shares_reconstruct(
			&shares[0..threshold as usize],
		);
		let reconstructed_quorum_key =
			RsaPair::from_der(&reconstructed).unwrap();

		let quorum_public_key = RsaPub::from_der(&output.quorum_key).unwrap();
		assert_eq!(reconstructed_quorum_key.public_key(), &quorum_public_key);
	}
}
