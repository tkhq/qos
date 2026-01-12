//! Enclave executor message types.

use qos_nsm::types::NsmResponse;

use super::{
	Approval, GenesisOutput, GenesisSet, ManifestEnvelope, ProtocolError,
};
use crate::protocol::ProtocolPhase;

/// Message types for communicating with protocol executor.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolMsg {
	/// A error from executing the protocol.
	ProtocolErrorResponse(ProtocolError),

	/// Request the status of the enclave.
	StatusRequest,
	/// Response for [`Self::StatusRequest`]
	StatusResponse(ProtocolPhase),

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
		/// Parameters for creating a Share Set
		set: GenesisSet,
		/// Optionally include a `qos_p256::P256Public` key for encrypting the
		/// quorum key too. Intended for disaster recovery.
		dr_key: Option<Vec<u8>>,
	},
	/// Response for Genesis Boot.
	BootGenesisResponse {
		/// COSE SIGN1 structure with Attestation Doc
		nsm_response: NsmResponse,
		/// Output from the Genesis flow.
		genesis_output: Box<GenesisOutput>,
	},

	/// Post a quorum key shard
	ProvisionRequest {
		/// Quorum Key share encrypted to the Ephemeral Key.
		share: Vec<u8>,
		/// Approval of the manifest from a member of the share set.
		approval: Approval,
	},
	/// Response to a Provision Request
	ProvisionResponse {
		/// If the Quorum key was reconstructed. False indicates still waiting
		/// for the Kth share.
		reconstructed: bool,
	},

	/// Proxy the encoded `data` to the secure app.
	ProxyRequest {
		/// Encoded data that will be sent from the nitro enclave server to
		/// the secure app.
		data: Vec<u8>,
	},
	/// Response to the proxy request
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
		/// Manifest Envelope, if it exists, otherwise None.
		manifest_envelope: Option<Box<ManifestEnvelope>>,
	},

	/// Execute a key forward attestation request
	BootKeyForwardRequest {
		/// Manifest with approvals
		manifest_envelope: Box<ManifestEnvelope>,
		/// Pivot binary
		pivot: Vec<u8>,
	},
	/// Response to a key forward attestation request
	BootKeyForwardResponse {
		/// Should be `[NsmResponse::Attestation`]
		nsm_response: NsmResponse,
	},

	/// Request a quorum key as part of the "key forwarding" flow.
	ExportKeyRequest {
		/// Manifest of the enclave requesting the quorum key.
		manifest_envelope: Box<ManifestEnvelope>,
		/// Attestation document from the enclave requesting the quorum key. We
		/// assume this attestation document contains a hash of the given
		/// manifest in the user data field.
		cose_sign1_attestation_doc: Vec<u8>,
	},
	/// Response to [`Self::ExportKeyRequest`]
	ExportKeyResponse {
		/// Quorum key encrypted to the Ephemeral Key from the submitted
		/// attestation document.
		encrypted_quorum_key: Vec<u8>,
		/// Signature over the encrypted quorum key.
		signature: Vec<u8>,
	},

	/// Inject a key into an enclave
	InjectKeyRequest {
		/// Quorum key encrypted to the Ephemeral Key of the enclave this
		/// request is being sent to.
		encrypted_quorum_key: Vec<u8>,
		/// Signature over the encrypted quorum key.
		signature: Vec<u8>,
	},
	/// Successful response to [`Self::InjectKeyRequest`].
	InjectKeyResponse,

	/// Fetch the manifest envelope, if it exists.
	ManifestEnvelopeRequest,
	/// Successful response to [`Self::ManifestEnvelopeRequest`].
	ManifestEnvelopeResponse {
		/// The manifest envelope used to boot the enclave. This will be `None`
		/// if the manifest envelope does not exist.
		manifest_envelope: Box<Option<ManifestEnvelope>>,
	},
}

impl std::fmt::Display for ProtocolMsg {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ProtocolErrorResponse(_) => {
				write!(f, "ProtocolErrorResponse")
			}
			Self::StatusRequest => write!(f, "StatusRequest"),
			Self::StatusResponse(_) => {
				write!(f, "StatusResponse")
			}
			Self::BootStandardRequest { .. } => {
				write!(f, "BootStandardRequest")
			}
			Self::BootStandardResponse { .. } => {
				write!(f, "BootStandardResponse")
			}
			Self::BootGenesisRequest { .. } => {
				write!(f, "BootGenesisRequest")
			}
			Self::BootGenesisResponse { .. } => {
				write!(f, "BootGenesisResponse")
			}
			Self::ProvisionRequest { .. } => {
				write!(f, "ProvisionRequest")
			}
			Self::ProvisionResponse { reconstructed } => {
				write!(
					f,
					"ProvisionResponse{{ reconstructed: {reconstructed} }}"
				)
			}
			Self::ProxyRequest { .. } => {
				write!(f, "ProxyRequest")
			}
			Self::ProxyResponse { .. } => {
				write!(f, "ProxyResponse")
			}
			Self::LiveAttestationDocRequest { .. } => {
				write!(f, "LiveAttestationDocRequest")
			}
			Self::LiveAttestationDocResponse { .. } => {
				write!(f, "LiveAttestationDocResponse")
			}
			Self::BootKeyForwardRequest { .. } => {
				write!(f, "BootKeyForwardRequest")
			}
			Self::BootKeyForwardResponse { nsm_response } => match nsm_response
			{
				NsmResponse::Attestation { .. } => write!(
					f,
					"BootKeyForwardResponse {{ nsm_response: Attestation }}"
				),
				NsmResponse::Error(ecode) => write!(
					f,
					"BootKeyForwardResponse {{ nsm_response: Error({ecode:?}) }}"
				),
				_ => write!(
					f,
					"BootKeyForwardResponse {{ nsm_response: Other }}" // this shouldn't really show up
				),
			},
			Self::ExportKeyRequest { .. } => {
				write!(f, "ExportKeyRequest")
			}
			Self::ExportKeyResponse { .. } => {
				write!(f, "ExportKeyResponse")
			}
			Self::InjectKeyRequest { .. } => {
				write!(f, "InjectKeyRequest")
			}
			Self::InjectKeyResponse { .. } => {
				write!(f, "InjectKeyResponse")
			}
			Self::ManifestEnvelopeRequest { .. } => {
				write!(f, "ManifestEnvelopeRequest")
			}
			Self::ManifestEnvelopeResponse { .. } => {
				write!(f, "ManifestEnvelopeResponse")
			}
		}
	}
}

#[cfg(test)]
mod test {
	use borsh::BorshDeserialize;

	use super::*;

	#[test]
	fn boot_genesis_response_deserialize() {
		let nsm_response = NsmResponse::LockPCR;

		let vec = borsh::to_vec(&nsm_response).unwrap();
		let test = NsmResponse::try_from_slice(&vec).unwrap();
		assert_eq!(nsm_response, test);

		let genesis_response = ProtocolMsg::BootGenesisResponse {
			nsm_response,
			genesis_output: Box::new(GenesisOutput {
				quorum_key: vec![3, 2, 1],
				member_outputs: vec![],
				recovery_permutations: vec![],
				threshold: 2,
				dr_key_wrapped_quorum_key: None,
				quorum_key_hash: [22; 64],
				test_message_ciphertext: vec![],
				test_message_signature: vec![],
				test_message: vec![],
			}),
		};

		let vec = borsh::to_vec(&genesis_response).unwrap();
		let test = ProtocolMsg::try_from_slice(&vec).unwrap();

		assert_eq!(test, genesis_response);
	}
}
