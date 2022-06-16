//! Enclave executor message types.

use crate::protocol::{
	attestor::types::{NsmRequest, NsmResponse},
	services::{
		boot::ManifestEnvelope,
		genesis::{GenesisOutput, GenesisSet},
	},
	ProtocolError,
};

/// Message types for communicating with protocol executor.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolMsg {
	/// A error from executing the protocol.
	ProtocolErrorResponse(ProtocolError),

	/// TODO: remove
	NsmRequest {
		/// A [`NsmRequest`]
		nsm_request: NsmRequest,
	},
	/// TODO: remove
	NsmResponse {
		/// A [`NsmResponse`]
		nsm_response: NsmResponse,
	},

	/// Request was successful. TODO: remove
	SuccessResponse,
	/// TODO: Error response should hold a protocol error, Remove
	ErrorResponse,

	/// Request the status of the enclave.
	StatusRequest,
	/// Response for [`StatusRequest`]
	StatusResponse(super::ProtocolPhase),

	/// Execute Standard Boot.
	BootStandardRequest {
		/// Manifest with approvals
		manifest_envelope: Box<ManifestEnvelope>,
		/// Pivot binary
		pivot: Vec<u8>,
	},
	/// Response for Standard Boot.
	BootStandardResponse {
		/// Should be `[NsmResponse::Attestation`]
		nsm_response: NsmResponse,
	},

	/// Execute Genesis Boot.
	BootGenesisRequest {
		/// Parameters for creating a Quorum Set
		set: GenesisSet,
	},
	/// Response for Genesis Boot.
	BootGenesisResponse {
		/// COSE SIGN1 structure with Attestation Doc
		nsm_response: NsmResponse,
		/// Output from the Genesis flow.
		genesis_output: GenesisOutput,
	},

	/// Post a quorum key shard
	ProvisionRequest {
		/// Quorum Key share encrypted to the Ephemeral Key.
		share: Vec<u8>,
	},
	/// Response to a Provision Request
	ProvisionResponse {
		/// If the Quorum key was reconstructed. False indicates still waiting
		/// for the Kth share.
		reconstructed: bool,
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
