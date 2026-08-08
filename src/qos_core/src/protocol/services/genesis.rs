//! Genesis boot logic and types.

use std::{fmt, iter::zip};

use qos_crypto::{sha_256, sha_512};
use qos_nsm::types::{NsmRequest, NsmResponse};
use qos_p256::{P256Pair, P256Public};
use serde::{Deserialize, Serialize};

use crate::protocol::{
	ProtocolError, ProtocolState, QosHash, services::boot::QuorumMember,
};

const QOS_TEST_MESSAGE: &[u8] = b"qos-test-message";

/// Domain separation tag for [`genesis_request_commitment`].
const GENESIS_REQUEST_COMMITMENT_DOMAIN: &str =
	"qos::genesis-request-commitment::v1";

/// The shape committed to by [`genesis_request_commitment`], hashed as QOS
/// canonical JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenesisRequestCommitment<'a> {
	domain: &'static str,
	set: &'a GenesisSet,
	#[serde(skip_serializing_if = "Option::is_none")]
	dr_key: Option<String>,
}

/// Compute the domain separated commitment over the exact genesis boot
/// request: the [`GenesisSet`] and the optional DR key.
///
/// # Panics
///
/// Panics if canonical JSON serialization fails; not expected for this shape.
#[must_use]
pub fn genesis_request_commitment(
	set: &GenesisSet,
	dr_key: Option<&[u8]>,
) -> [u8; 32] {
	let commitment = GenesisRequestCommitment {
		domain: GENESIS_REQUEST_COMMITMENT_DOMAIN,
		set,
		dr_key: dr_key.map(qos_hex::encode),
	};
	sha_256(&qos_json::to_vec(&commitment).expect(
		"`GenesisRequestCommitment` serializes to canonical JSON. qed.",
	))
}

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(
	PartialEq,
	Debug,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct GenesisSet {
	/// Share Set Member's who's production key will be used to encrypt Genesis
	/// flow outputs.
	pub members: Vec<QuorumMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	#[serde(with = "qos_json::string_or_numeric")]
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
struct MemberShard {
	/// Member of the Setup Set.
	member: QuorumMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	#[serde(with = "qos_hex::serde")]
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
	PartialEq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub struct RecoveredPermutation(Vec<MemberShard>);

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
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
	/// Quorum Member specific outputs from the genesis ceremony.
	pub member_outputs: Vec<GenesisMemberOutput>,
	/// All successfully `RecoveredPermutation`s completed during the genesis
	/// process.
	pub recovery_permutations: Vec<RecoveredPermutation>,
	/// The threshold, K, used to generate the shards.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// The quorum key encrypted to the DR key. None if no DR Key was provided
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "qos_hex::serde::option"
	)]
	pub dr_key_wrapped_quorum_key: Option<Vec<u8>>,
	/// Hash of the quorum key secret
	#[serde(with = "qos_hex::serde")]
	pub quorum_key_hash: [u8; 64],
	/// Test message encrypted to the quorum public key.
	#[serde(with = "qos_hex::serde")]
	pub test_message_ciphertext: Vec<u8>,
	/// Signature over the test message by the quorum key.
	#[serde(with = "qos_hex::serde")]
	pub test_message_signature: Vec<u8>,
	/// The message that was used to generate [`Self::test_message_signature`]
	/// and [`Self::test_message_ciphertext`]
	#[serde(with = "qos_hex::serde")]
	pub test_message: Vec<u8>,
	/// Commitment over the exact boot genesis request the enclave received.
	/// See [`genesis_request_commitment`]. Intentionally has no serde/borsh
	/// default so pre-commitment peers and outputs fail closed on decode.
	#[serde(with = "qos_hex::serde")]
	pub request_commitment: [u8; 32],
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

// How many permutations of `threshold` keys should we use
// to reconstruct the original Quorum Key?
pub(in crate::protocol) fn boot_genesis(
	state: &mut ProtocolState,
	genesis_set: &GenesisSet,
	maybe_dr_key: Option<Vec<u8>>,
) -> Result<(GenesisOutput, NsmResponse), ProtocolError> {
	super::boot::ensure_unique_members(&genesis_set.members)?;

	let request_commitment =
		genesis_request_commitment(genesis_set, maybe_dr_key.as_deref());

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
			let encrypted_quorum_key_share = personal_pub.encrypt(&share[..])?;

			Ok(GenesisMemberOutput {
				share_set_member,
				encrypted_quorum_key_share,
				share_hash: sha_512(&share[..]),
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
		request_commitment,
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

	#[test]
	fn boot_genesis_works() {
		let handles = Handles::new(
			"EPH".to_string(),
			"QUO".to_string(),
			"MAN".to_string(),
			"PIV".to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm::new()), handles.clone(), None);
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
		let shares: Vec<zeroize::Zeroizing<Vec<u8>>> = zipped
			.map(|(output, pair)| {
				let decrypted_share =
					pair.decrypt(&output.encrypted_quorum_key_share).unwrap();

				assert_eq!(sha_512(&decrypted_share[..]), output.share_hash);

				decrypted_share
			})
			.collect();

		let reconstructed: zeroize::Zeroizing<[u8; MASTER_SEED_LEN]> =
			zeroize::Zeroizing::new(
				qos_crypto::shamir::shares_reconstruct(
					&shares[0..threshold as usize],
				)
				.unwrap()[..]
					.try_into()
					.unwrap(),
			);
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
		assert_eq!(&test_message_plaintext[..], QOS_TEST_MESSAGE);
		quorum_public_key
			.verify(QOS_TEST_MESSAGE, &output.test_message_signature)
			.unwrap();

		let quorum_key_hash =
			sha_512(qos_hex::encode(&reconstructed[..]).as_bytes());
		assert_eq!(quorum_key_hash, output.quorum_key_hash);
	}

	#[test]
	fn boot_genesis_rejects_duplicate_members() {
		let handles = Handles::new(
			"EPH2".to_string(),
			"QUO2".to_string(),
			"MAN2".to_string(),
			"PIV2".to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm::new()), handles, None);
		let member_pair = P256Pair::generate().unwrap();

		// The same public key under two different aliases must be rejected.
		let genesis_set = GenesisSet {
			members: vec![
				QuorumMember {
					alias: "alias-a".to_string(),
					pub_key: member_pair.public_key().to_bytes(),
				},
				QuorumMember {
					alias: "alias-b".to_string(),
					pub_key: member_pair.public_key().to_bytes(),
				},
			],
			threshold: 2,
		};

		let err =
			boot_genesis(&mut protocol_state, &genesis_set, None).unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateQuorumMember);
	}

	fn test_member(alias: &str, key_byte: u8) -> QuorumMember {
		QuorumMember { alias: alias.to_string(), pub_key: vec![key_byte; 33] }
	}

	fn test_set() -> GenesisSet {
		GenesisSet {
			members: vec![test_member("a", 1), test_member("b", 2)],
			threshold: 2,
		}
	}

	#[test]
	fn genesis_request_commitment_binds_the_request() {
		let base = test_set();
		let base_commitment = genesis_request_commitment(&base, None);

		assert_eq!(genesis_request_commitment(&base, None), base_commitment);

		let mut altered = base.clone();
		altered.threshold = 1;
		assert_ne!(genesis_request_commitment(&altered, None), base_commitment);

		let mut altered = base.clone();
		altered.members[1] = test_member("b", 3);
		assert_ne!(genesis_request_commitment(&altered, None), base_commitment);

		let mut altered = base.clone();
		altered.members.reverse();
		assert_ne!(genesis_request_commitment(&altered, None), base_commitment);

		let mut altered = base.clone();
		altered.members.push(test_member("c", 3));
		assert_ne!(genesis_request_commitment(&altered, None), base_commitment);

		let some_a = genesis_request_commitment(&base, Some(&[7; 65]));
		let some_b = genesis_request_commitment(&base, Some(&[8; 65]));
		let some_empty = genesis_request_commitment(&base, Some(&[]));
		assert_ne!(base_commitment, some_a);
		assert_ne!(some_a, some_b);
		assert_ne!(base_commitment, some_empty);
	}

	#[test]
	fn boot_genesis_output_commits_to_the_exact_request() {
		let handles = Handles::new(
			"EPH".to_string(),
			"QUO".to_string(),
			"MAN".to_string(),
			"PIV".to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm::new()), handles, None);

		let members = (1..=3)
			.map(|i| QuorumMember {
				alias: format!("member{i}"),
				pub_key: P256Pair::generate().unwrap().public_key().to_bytes(),
			})
			.collect();
		let genesis_set = GenesisSet { members, threshold: 2 };
		let dr_key = P256Pair::generate().unwrap().public_key().to_bytes();

		let (output, _) = boot_genesis(
			&mut protocol_state,
			&genesis_set,
			Some(dr_key.clone()),
		)
		.unwrap();
		assert_eq!(
			output.request_commitment,
			genesis_request_commitment(&genesis_set, Some(&dr_key))
		);

		let mut tampered = output.clone();
		tampered.request_commitment = [0; 32];
		assert_ne!(tampered.qos_hash(), output.qos_hash());

		let (output, _) =
			boot_genesis(&mut protocol_state, &genesis_set, None).unwrap();
		assert_eq!(
			output.request_commitment,
			genesis_request_commitment(&genesis_set, None)
		);
	}
}
