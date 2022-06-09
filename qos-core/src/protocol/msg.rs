//! Enclave I/O message format and serialization.

pub use aws_nitro_enclaves_nsm_api::api::{
	Digest as NsmDigest, Request as NsmRequest, Response as NsmResponse,
};

#[derive(Debug, PartialEq)]
pub enum ProtocolError {
	InvalidShare,
	ReconstructionError,
	IOError,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum ProtocolMsg {
	SuccessResponse,
	// TODO: Error response should hold a protocol error
	ErrorResponse,
	EmptyRequest,
	EmptyResponse,
	EchoRequest(Echo),
	EchoResponse(Echo),
	ProvisionRequest(Provision),
	ReconstructRequest,
	NsmRequest(NsmRequest),
	NsmResponse(NsmResponse),
	LoadRequest(Load),
	BootInstruction(BootInstruction),
}

impl PartialEq for ProtocolMsg {
	fn eq(&self, other: &Self) -> bool {
		serde_cbor::to_vec(self).expect("ProtocolMsg serializes. qed.")
			== serde_cbor::to_vec(other).expect("ProtocolMsg serializes. qed.")
	}

	fn ne(&self, other: &Self) -> bool {
		!self.eq(other)
	}
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Echo {
	pub data: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Provision {
	pub share: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureWithPubKey {
	/// Signature
	pub signature: Vec<u8>,
	/// Path to the file containing the public key associated with this
	/// signature.
	pub path: String,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct Load {
	/// The executable to pivot to
	pub executable: Vec<u8>,
	//// Signatures of the data
	pub signatures: Vec<SignatureWithPubKey>,
}

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
		qos_crypto::sha_256_hash(&serde_cbor::to_vec(&self).expect("decodes"))
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

pub struct GenesisMemberOutput {
	pub alias: String,
	pub encrypted_quorum_key_share: Vec<u8>,
	pub encrypted_personal_key: Vec<u8>
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

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BootInstruction {
	Standard { manifest_envelope: ManifestEnvelope, pivot: Vec<u8> },
	Genesis { config: GenesisConfig },
}
