//! Genesis boot logic and types.

use std::iter::zip;

use qos_crypto::sha_512;
use qos_nsm::types::{NsmRequest, NsmResponse};
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{ProtocolError, ProtocolState, QosHash};

pub use crate::protocol::internal::{
	GenesisMemberOutput, GenesisOutput, GenesisSet, RecoveredPermutation,
};

const QOS_TEST_MESSAGE: &[u8] = b"qos-test-message";

// How many permutations of `threshold` keys should we use
// to reconstruct the original Quorum Key?
pub(in crate::protocol) fn boot_genesis(
	state: &mut ProtocolState,
	genesis_set: &GenesisSet,
	maybe_dr_key: Option<Vec<u8>>,
) -> Result<(GenesisOutput, NsmResponse), ProtocolError> {
	let quorum_pair = P256Pair::generate()?;
	let master_seed = &quorum_pair.to_master_seed()[..];

	let shares = qos_crypto::shamir::shares_generate(
		master_seed,
		genesis_set.members.len(),
		genesis_set.threshold as usize,
	)
	.map_err(|e| ProtocolError::QosCrypto(format!("{e:?}")))?;

	let member_outputs: Result<Vec<_>, _> = zip(shares, genesis_set.members.iter().cloned())
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
		.collect();

	let dr_key_wrapped_quorum_key = if let Some(dr_key) = maybe_dr_key {
		let dr_public = P256Public::from_bytes(&dr_key)
			.map_err(ProtocolError::InvalidP256DRKey)?;
		Some(dr_public.encrypt(master_seed)?)
	} else {
		None
	};

	let hex_master_seed = qos_hex::encode(master_seed);
	let genesis_output = GenesisOutput {
		member_outputs: member_outputs?,
		quorum_key: quorum_pair.public_key().to_bytes(),
		threshold: genesis_set.threshold,
		// TODO: generate N choose K recovery permutations
		recovery_permutations: vec![],
		dr_key_wrapped_quorum_key,
		quorum_key_hash: sha_512(hex_master_seed.as_bytes()),
		test_message_ciphertext: quorum_pair
			.public_key()
			.encrypt(QOS_TEST_MESSAGE)?,
		test_message_signature: quorum_pair.sign(QOS_TEST_MESSAGE)?,
		test_message: QOS_TEST_MESSAGE.to_vec(),
	};

	let nsm_response = {
		let request = NsmRequest::Attestation {
			user_data: Some(genesis_output.qos_hash().to_vec()),
			nonce: None,
			public_key: None,
		};
		state.attestor.nsm_process_request(request)
	};

	Ok((genesis_output, nsm_response))
}

#[cfg(test)]
mod test {
	use qos_nsm::mock::MockNsm;
	use qos_p256::MASTER_SEED_LEN;

	use super::*;
	use crate::handles::Handles;
	use crate::protocol::internal::QuorumMember;

	#[test]
	fn boot_genesis_works() {
		let handles = Handles::new(
			"EPH".to_string(),
			"QUO".to_string(),
			"MAN".to_string(),
			"PIV".to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);
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
			boot_genesis(&mut protocol_state, &genesis_set, None).unwrap();
		let zipped = std::iter::zip(output.member_outputs, member_pairs);
		let shares: Vec<Vec<u8>> = zipped
			.map(|(output, pair)| {
				let decrypted_share =
					&pair.decrypt(&output.encrypted_quorum_key_share).unwrap();

				assert_eq!(sha_512(decrypted_share), output.share_hash);

				decrypted_share.clone()
			})
			.collect();

		let reconstructed: [u8; MASTER_SEED_LEN] =
			qos_crypto::shamir::shares_reconstruct(
				&shares[0..threshold as usize],
			)
			.unwrap()
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

		let test_message_plaintext = reconstructed_quorum_key
			.decrypt(&output.test_message_ciphertext)
			.unwrap();
		assert_eq!(test_message_plaintext, QOS_TEST_MESSAGE);
		quorum_public_key
			.verify(QOS_TEST_MESSAGE, &output.test_message_signature)
			.unwrap();

		let quorum_key_hash =
			sha_512(qos_hex::encode(&reconstructed).as_bytes());
		assert_eq!(quorum_key_hash, output.quorum_key_hash);
	}
}
