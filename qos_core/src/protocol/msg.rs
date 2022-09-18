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
	/// Response for [`Self::StatusRequest`]
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

	/// Proxy the encoded `data` to the secure app.
	ProxyRequest {
		/// Encoded data that will be sent from the nitro enclave serverga to
		/// the secure app.
		data: Vec<u8>,
	},
	/// Response to the proxy request.
	ProxyResponse {
		/// Encoded data the secure app responded with to the nitro enclave
		/// server.
		data: Vec<u8>,
	},

	/// Request an attestation document that includes references to the
	/// manifest (in `user_data`) and the ephemeral key (`public_key`).
	LiveAttestationDocRequest,
	/// Response to live attestation document request.
	LiveAttestationDocResponse {
		/// COSE SIGN1 structure with Attestation Doc
		nsm_response: NsmResponse,
	},

	/// A request to a New Node to initiate the chained boot process.
	BootChainRequest {
		/// The manifest envelope for the new node.
		manifest_envelope: ManifestEnvelope,
		/// Pivot binary
		pivot: Vec<u8>,
	},

	/// A request from a new node to an original node for the quorum key.
	///
	/// Also the the response to a BootChainRequest TODO: does this make sense?
	/// Should we have another type for the response which doesn't include the
	/// manifest envelope?
	ChainQuorumKeyRequest {
		/// COSE SIGN1 structure containing the attestation doc and a signature
		/// from the NSM end entity certificate.
		///
		/// The user data field should have the hash of the manifest. The
		/// public key field should have the new nodes ephemeral key, which
		/// should be used to encrypt the
		cose_sign1_attestation_doc: Vec<u8>,
		/// The manifest Envelope for the new node making the request. This is
		/// referenced as the user data in the attestation document.
		manifest_envelope: ManifestEnvelope,
	},

	/// The response to a chain quorum
	InjectQuorumKeyRequest {
		/// PEM encoded quorum private key, encrypted to the ephemeral key in
		/// the attestation document request.
		encrypted_quorum_key: Vec<u8>,
	},
	/// A quorum key was successfully injected.
	InjectQuorumKeyResponse,
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
				threshold: 2,
			},
		};

		let vec = genesis_response.try_to_vec().unwrap();
		let test = ProtocolMsg::try_from_slice(&vec).unwrap();

		assert_eq!(test, genesis_response);
	}
}
