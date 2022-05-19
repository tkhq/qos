//! Enclave I/O message format and serialization.
use super::{NsmRequest, NsmResponse};

#[derive(Debug, PartialEq)]
pub enum ProtocolError {
	InvalidShare,
	ReconstructionError,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProtocolMsg {
	SuccessResponse,
	// TODO: Error response should hold a protocol error
	ErrorResponse,
	EmptyRequest,
	EmptyResponse,
	EchoRequest(Echo),
	EchoResponse(Echo),
	ProvisionRequest(ProvisionRequest),
	ReconstructRequest,
	NsmRequest(NsmRequest),
	NsmResponse(NsmResponse),
	LoadRequest(Load),
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Echo {
	pub data: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisionRequest {
	pub share: Vec<u8>,
}
#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisionResponse {}

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
	/// Some data
	pub data: Vec<u8>,
	//// Signatures of the data
	pub signatures: Vec<SignatureWithPubKey>,
}
