use std::iter::zip;

use qos_crypto::{RsaPair, RsaPub};

use super::{Hash256, ProtocolError};

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisMemberOutput {
	/// The Quorum Member whom's Setup Key was used.
	pub setup_member: SetupMember,
	/// Quorum Key Share encrypted to the Personal Key.
	pub encrypted_quorum_key_share: Vec<u8>,
	/// Personal Key encrypted to the Quorum Member's Setup Key.
	pub encrypted_personal_key: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SetupMember {
	/// A unique UTF-8 encoded string to help Human participants to identify
	/// this member.
	pub alias: String,
	/// A Setup Key that will be used by the Genesis flow to encrypt a
	/// Personal Key.
	pub pub_key: Vec<u8>,
}

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisSet {
	/// Quorum Member's whoms setup key will be used to encrypt Genesis flow
	/// outputs.
	pub members: Vec<SetupMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	pub threshold: u32,
}


#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MemberShard {
	// TODO: is this taking up too much unnecessary space?
	member: SetupMember,
	shard: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveredPermutation(Vec<MemberShard>);

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisOutput {
	/// Quorum Key - RSA public key
	pub quorum_key: Vec<u8>,
	/// Quorum Member specific outputs from the genesis ceremony.
	pub member_outputs: Vec<GenesisMemberOutput>,
	pub recovery_permutations: Vec<RecoveredPermutation>,
}

impl GenesisOutput {
	pub fn hash(&self) -> Hash256 {
		qos_crypto::sha_256(
			&serde_cbor::to_vec(&self)
				.expect("`Manifest` serializes with cbor"),
		)
	}

	// TODO: Recovery logic!
	// How many permutations of `threshold` keys should we use
	// to reconstruct the original Quorum Key?
	//
	// TODO: Disaster recovery logic!
	// Maybe we can just accept 2 set configs, and one is the recovery set?``
	pub fn try_from(
		quorum_pair: &RsaPair,
		set: &GenesisSet,
	) -> Result<Self, ProtocolError> {
		let shares = qos_crypto::shares_generate(
			&quorum_pair.private_key_to_der()?,
			set.members.len(),
			set.threshold as usize,
		);

		let mut member_outputs = Vec::with_capacity(shares.len());
		let zipped = zip(shares, set.members.iter().cloned());
		for (share, setup_member) in zipped.clone() {
			// 1) generate Personal Key pair
			let personal_pair = RsaPair::generate()?;

			// 2) encrypt Personal Key to Setup Key
			let encrypted_personal_key = {
				let setup_key = RsaPub::from_der(&setup_member.pub_key)?;
				let personal_der = personal_pair
					.private_key_to_der()?;

				setup_key.envelope_encrypt(&personal_der)?
			};

			// 3) encrypt the Quorum Share to the Personal Key
			let encrypted_quorum_key_share =
				personal_pair.envelope_encrypt(&share)?;

			member_outputs.push(GenesisMemberOutput {
				setup_member,
				encrypted_personal_key,
				encrypted_quorum_key_share,
			});
		}

		Ok(Self {
			member_outputs,
			quorum_key: quorum_pair
				.public_key_to_der()?,
			// TODO: generate N choose K recovery permutations
			recovery_permutations: vec![]
		})
	}
}

// type Shard = Vec<u8>;
// fn generate_choose_k_permutations<T>(els: Vec<T>, k: usize) -> Vec<Vec<T>> {
// 	for i in 0..k {}
// }
