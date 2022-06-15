//! Enclave executor message types.

use super::{
	boot::ManifestEnvelope,
	genesis::{GenesisOutput, GenesisSet},
	NsmRequest, NsmResponse, ProtocolError,
};

/// Message types for communicating with protocol executor.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolMsg {
	/// The executor encountered an unrecoverable error.
	UnrecoverableErrorResponse,
	/// Could not process response because in unrecoverable phase. TODO: maybe
	/// remove
	InUnrecoverablePhaseResponse,

	/// A error from executing the protocol.
	ProtocolErrorResponse(ProtocolError),

	/// TODO: remove
	EmptyRequest,
	/// TODO: remove
	EmptyResponse,
	/// TODO: remove
	EchoRequest(Echo),
	/// TODO: remove
	EchoResponse(Echo),
	/// TODO: remove
	ReconstructRequest,
	/// TODO: remove
	NsmRequest(NsmRequest),
	/// TODO: remove
	NsmResponse(NsmResponse),
	/// TODO: remove
	LoadRequest(Load),
	/// Request was succesful. TODO: remove
	SuccessResponse,
	/// TODO: Error response should hold a protocol error, Remove
	ErrorResponse,

	/// Request the status of the enclave.
	StatusRequest,
	/// Response for [`StatusRequest`]
	StatusResponse(super::ProtocolPhase),

	/// Send the boot instruction.
	BootRequest(BootInstruction),
	/// Response for Standard Boot.
	BootStandardResponse(NsmResponse),
	/// Response for Genesis Boot.
	BootGenesisResponse {
		/// COSE SIGN1 structure with Attestation Doc
		nsm_response: NsmResponse,
		/// Output from the Genesis flow.
		genesis_output: GenesisOutput,
	},
	/// Post a quorum key shard
	ProvisionRequest(Provision),
}

/// TODO: remove
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Echo {
	/// TODO: remove
	pub data: Vec<u8>,
}

/// TODO: replace with provision service etc
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Provision {
	/// TODO: remove
	pub share: Vec<u8>,
}

/// TODO: remove
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

/// TODO: remove
#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Load {
	/// The executable to pivot to
	pub executable: Vec<u8>,
	/// Signatures of the data
	pub signatures: Vec<SignatureWithPubKey>,
}

/// Instruction for initiate the enclave boot interactive process.
#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum BootInstruction {
	/// Execute Standard Boot.
	Standard {
		/// Manifest with approvals
		manifest_envelope: Box<ManifestEnvelope>,
		/// Pivot binary
		pivot: Vec<u8>,
	},
	/// Execute Genesis Boot.
	Genesis {
		/// Parameters for creating a Quorum Set
		set: GenesisSet,
	},
}

#[cfg(test)]
mod test {
	use borsh::{BorshDeserialize, BorshSerialize};

	use super::*;

	#[test]
	fn boot_genesis_response_deserialize() {
		let nsm_response = NsmResponse::LockPCR;

		let vec = nsm_response.try_to_vec().unwrap();
		let test = NsmResponse::try_from_slice(&vec).unwrap();
		assert_eq!(nsm_response, test);

		let genesis_response = ProtocolMsg::BootGenesisResponse {
			nsm_response,
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
