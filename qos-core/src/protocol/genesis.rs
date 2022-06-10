#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisMemberOutput {
	pub setup_member: SetupMember,
	pub encrypted_quorum_key_share: Vec<u8>,
	pub encrypted_personal_key: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SetupMember {
	pub alias: String,
	pub pub_key: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SetupSet {
	pub members: Vec<SetupMember>,
	pub threshold: u32,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisConfig {
	pub setup_set: SetupSet,
}
