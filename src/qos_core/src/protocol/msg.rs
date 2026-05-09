//! Enclave executor message types.

use qos_nsm::types::NsmResponse;

use crate::protocol::{
	services::{
		boot::{Approval, VersionedManifestEnvelope},
		genesis::{GenesisOutput, GenesisSet},
	},
	ProtocolError,
};

/// Message types for communicating with protocol executor.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolMsg {
	/// A error from executing the protocol.
	ProtocolErrorResponse(ProtocolError),

	/// Request the status of the enclave.
	StatusRequest,
	/// Response for [`Self::StatusRequest`]
	StatusResponse(super::ProtocolPhase),

	/// Execute Standard Boot.
	BootStandardRequest {
		/// Versioned manifest with approvals.
		manifest_envelope: Box<VersionedManifestEnvelope>,
		/// Pivot binary
		#[serde(with = "qos_hex::serde")]
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
		#[serde(default, with = "qos_hex::serde")]
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
		#[serde(with = "qos_hex::serde")]
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
		#[serde(with = "qos_hex::serde")]
		data: Vec<u8>,
	},
	/// Response to the proxy request
	ProxyResponse {
		/// Encoded data the secure app responded with to the nitro enclave
		/// server.
		#[serde(with = "qos_hex::serde")]
		data: Vec<u8>,
	},

	/// Request an attestation document that includes references to the
	/// manifest (in `user_data`) and the ephemeral key (`public_key`).
	LiveAttestationDocRequest,
	/// Response to live attestation document request.
	LiveAttestationDocResponse {
		/// COSE SIGN1 structure with Attestation Doc
		nsm_response: NsmResponse,
		/// Versioned manifest envelope, if it exists, otherwise None.
		#[serde(default)]
		manifest_envelope: Option<Box<VersionedManifestEnvelope>>,
	},

	/// Execute a key forward attestation request
	BootKeyForwardRequest {
		/// Versioned manifest with approvals.
		manifest_envelope: Box<VersionedManifestEnvelope>,
		/// Pivot binary
		#[serde(with = "qos_hex::serde")]
		pivot: Vec<u8>,
	},
	/// Response to a key forward attestation request
	BootKeyForwardResponse {
		/// Should be `[NsmResponse::Attestation`]
		nsm_response: NsmResponse,
	},

	/// Request a quorum key as part of the "key forwarding" flow.
	ExportKeyRequest {
		/// Versioned manifest of the enclave requesting the quorum key.
		manifest_envelope: Box<VersionedManifestEnvelope>,
		/// Attestation document from the enclave requesting the quorum key. We
		/// assume this attestation document contains a hash of the given
		/// manifest in the user data field.
		#[serde(with = "qos_hex::serde")]
		cose_sign1_attestation_doc: Vec<u8>,
	},
	/// Response to [`Self::ExportKeyRequest`]
	ExportKeyResponse {
		/// Quorum key encrypted to the Ephemeral Key from the submitted
		/// attestation document.
		#[serde(with = "qos_hex::serde")]
		encrypted_quorum_key: Vec<u8>,
		/// Signature over the encrypted quorum key.
		#[serde(with = "qos_hex::serde")]
		signature: Vec<u8>,
	},

	/// Inject a key into an enclave
	InjectKeyRequest {
		/// Quorum key encrypted to the Ephemeral Key of the enclave this
		/// request is being sent to.
		#[serde(with = "qos_hex::serde")]
		encrypted_quorum_key: Vec<u8>,
		/// Signature over the encrypted quorum key.
		#[serde(with = "qos_hex::serde")]
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
		#[serde(default)]
		manifest_envelope: Box<Option<VersionedManifestEnvelope>>,
	},

	/// Request the QOS version and git commit of the running enclave.
	VersionRequest,
	/// Response for [`Self::VersionRequest`].
	VersionResponse {
		/// `qos_core` crate semver, captured at compile time from
		/// `CARGO_PKG_VERSION`.
		version: String,
		/// Git commit captured at build time. Sourced from the
		/// `QOS_GIT_COMMIT` env var (set by the build caller) with a
		/// `git rev-parse --short HEAD` fallback. May be `"unknown"` if
		/// neither was available at build time.
		commit: String,
	},
}

impl ProtocolMsg {
	/// Encode this protocol message as RFC 8785 canonical JSON bytes.
	///
	/// # Panics
	///
	/// Panics only if the protocol message cannot be serialized, which would be
	/// a bug in the message schema.
	#[must_use]
	pub fn to_canonical_json_vec(&self) -> Vec<u8> {
		qos_json::to_vec(self)
			.expect("ProtocolMsg can always be serialized. qed.")
	}

	/// Decode a protocol message from JSON bytes.
	///
	/// # Errors
	///
	/// Returns an error if the bytes are not valid JSON for a protocol
	/// message.
	pub fn from_json_slice(bytes: &[u8]) -> serde_json::Result<Self> {
		serde_json::from_slice(bytes)
	}
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
			Self::VersionRequest => write!(f, "VersionRequest"),
			Self::VersionResponse { version, commit } => {
				write!(
					f,
					"VersionResponse{{ version: {version}, commit: {commit} }}"
				)
			}
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn boot_genesis_response_deserialize() {
		let nsm_response = NsmResponse::LockPcr;

		let vec = qos_json::to_vec(&nsm_response).unwrap();
		let test: NsmResponse = serde_json::from_slice(&vec).unwrap();
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

		let vec = genesis_response.to_canonical_json_vec();
		let test = ProtocolMsg::from_json_slice(&vec).unwrap();

		assert_eq!(test, genesis_response);
	}

	#[test]
	fn optional_fields_are_omitted_and_bytes_are_hex() {
		let msg = ProtocolMsg::BootGenesisRequest {
			set: GenesisSet { members: vec![], threshold: 1 },
			dr_key: None,
		};
		assert_eq!(
			qos_json::to_string(&msg).unwrap(),
			r#"{"bootGenesisRequest":{"set":{"members":[],"threshold":"1"}}}"#
		);

		let msg = ProtocolMsg::ProxyRequest { data: vec![0xde, 0xad] };
		assert_eq!(
			msg.to_canonical_json_vec(),
			br#"{"proxyRequest":{"data":"dead"}}"#
		);
	}

	#[test]
	fn version_response_round_trip() {
		let msg = ProtocolMsg::VersionResponse {
			version: "0.5.0".to_string(),
			commit: "abc1234".to_string(),
		};
		let vec = msg.to_canonical_json_vec();
		let decoded = ProtocolMsg::from_json_slice(&vec).unwrap();
		assert_eq!(msg, decoded);
	}

	#[test]
	fn version_request_round_trip() {
		let msg = ProtocolMsg::VersionRequest;
		let vec = msg.to_canonical_json_vec();
		let decoded = ProtocolMsg::from_json_slice(&vec).unwrap();
		assert_eq!(msg, decoded);
	}

	#[test]
	fn manifest_envelope_response_backcompat_with_missing_field() {
		let raw = br#"{"manifestEnvelopeResponse":{}}"#;
		let decoded: ProtocolMsg = serde_json::from_slice(raw).unwrap();
		match decoded {
			ProtocolMsg::ManifestEnvelopeResponse { manifest_envelope } => {
				assert_eq!(*manifest_envelope, None);
			}
			other => panic!("unexpected decoded message: {other:?}"),
		}
	}
}
