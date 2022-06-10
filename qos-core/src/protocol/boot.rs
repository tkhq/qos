pub type Hash256 = [u8; 32];

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NitroConfig {
	/// VSOCK Context ID - component of VSockAddress.
	pub vsock_cid: u16,
	/// VSOCK Port - component of VSockAddress.
	pub vsock_port: u16,
	/// The hash of the enclave image file
	pub pcr0: Hash256,
	/// The hash of the Linux kernel and bootstrap
	pub pcr1: Hash256,
	/// The hash of the application
	pub pcr2: Hash256,
	/// DER encoded X509 AWS root certificate
	pub aws_root_certificate: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RestartPolicy {
	/// Never restart the pivot application
	Never,
	/// Always restart the pivot application
	Always,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PivotConfig {
	hash: Hash256,
	pub restart: RestartPolicy,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuorumMember {
	pub alias: String,
	pub pub_key: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuorumSet {
	pub threshold: u32,
	pub members: Vec<QuorumMember>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
	pub nonce: u32,
	pub namespace: String,
	pub enclave: NitroConfig,
	pub pivot: PivotConfig,
	pub quorum_key: Vec<u8>,
	pub quorum_set: QuorumSet,
}

impl Manifest {
	pub fn hash(&self) -> Hash256 {
		qos_crypto::sha_256(
			&serde_cbor::to_vec(&self)
				.expect("`Manifest` serializes with cbor"),
		)
	}
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Approval {
	pub signature: Vec<u8>,
	pub member: QuorumMember,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEnvelope {
	pub manifest: Manifest,
	pub approvals: Vec<Approval>,
}
