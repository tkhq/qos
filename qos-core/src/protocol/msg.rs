//! Enclave I/O message format.

use super::{
	boot::ManifestEnvelope,
	genesis::{GenesisOutput, GenesisSet},
	NsmRequest, NsmResponse, ProtocolError,
};

#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
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
	BootGenesisResponse {
		/// COSE SIGN1 structure with Attestation Doc
		attestation_doc: NsmResponse,
		/// Output from the Genesis flow.
		genesis_output: GenesisOutput,
	},

	ProtocolErrorResponse(ProtocolError),
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Echo {
	pub data: Vec<u8>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Provision {
	pub share: Vec<u8>,
}

#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SignatureWithPubKey {
	/// Signature
	pub signature: Vec<u8>,
	/// Path to the file containing the public key associated with this
	/// signature.
	pub path: String,
}

#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Load {
	/// The executable to pivot to
	pub executable: Vec<u8>,
	//// Signatures of the data
	pub signatures: Vec<SignatureWithPubKey>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum BootInstruction {
	Standard { manifest_envelope: Box<ManifestEnvelope>, pivot: Vec<u8> },
	Genesis { set: GenesisSet },
}

#[cfg(test)]
mod test {
	use borsh::{BorshDeserialize, BorshSerialize};

	use super::*;

	#[test]
	fn boot_genesis_response_deserialize() {
		let nsm = NsmResponse::LockPCR;

		let vec = nsm.try_to_vec().unwrap();
		let test = NsmResponse::try_from_slice(&vec).unwrap();
		assert_eq!(nsm.try_to_vec().unwrap(), test.try_to_vec().unwrap());

		let genesis_response = ProtocolMsg::BootGenesisResponse {
			attestation_doc: nsm,
			genesis_output: GenesisOutput {
				quorum_key: vec![3, 2, 1],
				member_outputs: vec![],
				recovery_permutations: vec![],
			},
		};

		let vec = genesis_response.try_to_vec().unwrap();
		let test = ProtocolMsg::try_from_slice(&vec).unwrap();

		assert_eq!(test, genesis_response);
	}
}
