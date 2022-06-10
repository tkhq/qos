use super::Hash256;

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
pub struct GenesisOutput {
	/// Quorum Key - RSA public key
	pub quorum_key: Vec<u8>,
	/// Quorum Member specific outputs from the genesis ceremony.
	pub member_outputs: Vec<GenesisMemberOutput>,
}

impl GenesisOutput {
	pub fn hash(&self) -> Hash256 {
		qos_crypto::sha_256(
			&serde_cbor::to_vec(&self)
				.expect("`Manifest` serializes with cbor"),
		)
	}
}
