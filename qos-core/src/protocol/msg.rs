//! Enclave I/O message format and serialization.

pub use aws_nitro_enclaves_nsm_api::api::{
	Digest as NsmDigest, Request as NsmRequest, Response as NsmResponse,
};

use super::{boot::ManifestEnvelope, genesis::GenesisConfig};

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
	UnrecoverableErrorResponse,
	InUnrecoverablePhaseResponse,
	EmptyRequest,
	EmptyResponse,
	EchoRequest(Echo),
	EchoResponse(Echo),
	ProvisionRequest(Provision),
	ReconstructRequest,
	NsmRequest(NsmRequest),
	NsmResponse(NsmResponse),
	LoadRequest(Load),

	StatusRequest,
	StatusResponse(super::ProtocolPhase),

	BootRequest(BootInstruction),
	BootStandardResponse(NsmResponse),
	BootGenesisResponse,
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

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BootInstruction {
	Standard { manifest_envelope: ManifestEnvelope, pivot: Vec<u8> },
	Genesis { config: GenesisConfig },
}
