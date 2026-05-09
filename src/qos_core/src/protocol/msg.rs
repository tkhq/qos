//! Enclave executor message types.

use std::ops::{Deref, DerefMut};

use borsh::{BorshDeserialize, BorshSerialize};
use qos_nsm::types::NsmResponse;
use serde::{de::DeserializeOwned, Serialize};

use crate::protocol::{
	services::{
		boot::{Approval, VersionedManifestEnvelope},
		genesis::{GenesisOutput, GenesisSet},
	},
	ProtocolError,
};

/// Borsh wrapper that carries a Rust value as JSON bytes on the wire.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct JsonBytes<T>(T);

impl<T> JsonBytes<T> {
	/// Wrap a value for JSON-byte Borsh transport.
	#[must_use]
	pub fn new(value: T) -> Self {
		Self(value)
	}

	/// Consume the wrapper and return the inner value.
	#[must_use]
	pub fn into_inner(self) -> T {
		self.0
	}
}

impl<T> Deref for JsonBytes<T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl<T> DerefMut for JsonBytes<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

impl<T> BorshSerialize for JsonBytes<T>
where
	T: Serialize,
{
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		let bytes =
			serde_json::to_vec(&self.0).map_err(borsh::io::Error::other)?;
		BorshSerialize::serialize(&bytes, writer)
	}
}

impl<T> BorshDeserialize for JsonBytes<T>
where
	T: DeserializeOwned,
{
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let bytes = Vec::<u8>::deserialize_reader(reader)?;
		let value =
			serde_json::from_slice(&bytes).map_err(borsh::io::Error::other)?;
		Ok(Self(value))
	}
}

/// Encoding used for a protocol message on the host/enclave wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMsgEncoding {
	/// Canonical QOS JSON.
	Json,
	/// Legacy Borsh.
	Borsh,
}

/// Message types for communicating with protocol executor.
#[derive(
	Debug,
	PartialEq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
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
		/// Manifest with approvals
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
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "qos_hex::serde::option"
		)]
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
		/// Manifest Envelope, if it exists, otherwise None.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		manifest_envelope: Option<Box<VersionedManifestEnvelope>>,
	},

	/// Execute a key forward attestation request
	BootKeyForwardRequest {
		/// Manifest with approvals
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
		/// Manifest of the enclave requesting the quorum key.
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
		#[serde(default, skip_serializing_if = "Option::is_none")]
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

	/// Borsh-only standard boot request with a JSON/storage-encoded manifest
	/// envelope and raw pivot bytes.
	#[serde(skip)]
	BootStandardJsonEnvelopeRequest {
		/// Manifest envelope encoded as JSON bytes in Borsh.
		manifest_envelope: Box<JsonBytes<VersionedManifestEnvelope>>,
		/// Pivot binary.
		pivot: Vec<u8>,
	},
}

impl ProtocolMsg {
	/// Decode a protocol message from canonical JSON or legacy Borsh bytes.
	///
	/// JSON is attempted first because it is the preferred wire format and it
	/// can represent v2 manifests. Borsh remains accepted for backwards
	/// compatibility with existing hosts and clients.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::ProtocolMsgDeserialization`] when `bytes`
	/// cannot be decoded as either canonical JSON or legacy Borsh.
	pub fn from_wire(
		bytes: &[u8],
	) -> Result<(Self, ProtocolMsgEncoding), ProtocolError> {
		if let Ok(msg) = qos_json::from_slice(bytes) {
			return Ok((msg, ProtocolMsgEncoding::Json));
		}

		<Self as borsh::BorshDeserialize>::try_from_slice(bytes)
			.map(|msg| (msg, ProtocolMsgEncoding::Borsh))
			.map_err(|_| ProtocolError::ProtocolMsgDeserialization)
	}

	/// Decode a protocol message from canonical JSON or legacy Borsh bytes,
	/// discarding the detected encoding.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::ProtocolMsgDeserialization`] when `bytes`
	/// cannot be decoded as either canonical JSON or legacy Borsh.
	pub fn from_wire_any(bytes: &[u8]) -> Result<Self, ProtocolError> {
		Self::from_wire(bytes).map(|(msg, _)| msg)
	}

	/// Encode this message in the requested wire format.
	///
	/// Legacy Borsh encoding cannot represent v2 manifests and returns an
	/// error for messages that contain them.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::InvalidMsg`] when the message cannot be
	/// encoded in the requested wire format.
	pub fn to_wire(
		&self,
		encoding: ProtocolMsgEncoding,
	) -> Result<Vec<u8>, ProtocolError> {
		match encoding {
			ProtocolMsgEncoding::Json => {
				qos_json::to_vec(self).map_err(|_| ProtocolError::InvalidMsg)
			}
			ProtocolMsgEncoding::Borsh => {
				borsh::to_vec(self).map_err(|_| ProtocolError::InvalidMsg)
			}
		}
	}

	/// Encode this message as canonical QOS JSON.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::InvalidMsg`] if JSON encoding fails.
	pub fn to_json_wire(&self) -> Result<Vec<u8>, ProtocolError> {
		self.to_wire(ProtocolMsgEncoding::Json)
	}

	/// Encode this message as legacy Borsh.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::InvalidMsg`] if Borsh encoding fails.
	pub fn to_borsh_wire(&self) -> Result<Vec<u8>, ProtocolError> {
		self.to_wire(ProtocolMsgEncoding::Borsh)
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
			Self::BootStandardJsonEnvelopeRequest { .. } => {
				write!(f, "BootStandardJsonEnvelopeRequest")
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
	use borsh::BorshDeserialize;
	use std::collections::BTreeSet;

	use super::*;
	use crate::protocol::services::boot::{
		ManifestEnvelopeV2, ManifestSet, ManifestV2, ManifestVersion,
		Namespace, NitroConfig, PivotConfigV2, PivotEnv, RestartPolicy,
		ShareSet,
	};

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

	#[test]
	fn version_response_round_trip() {
		let msg = ProtocolMsg::VersionResponse {
			version: "0.5.0".to_string(),
			commit: "abc1234".to_string(),
		};

		let vec = borsh::to_vec(&msg).unwrap();
		let decoded = ProtocolMsg::try_from_slice(&vec).unwrap();

		assert_eq!(msg, decoded);
	}

	#[test]
	fn version_request_round_trip() {
		let msg = ProtocolMsg::VersionRequest;

		let vec = borsh::to_vec(&msg).unwrap();
		let decoded = ProtocolMsg::try_from_slice(&vec).unwrap();

		assert_eq!(msg, decoded);
	}

	#[test]
	fn json_wire_round_trips_numeric_protocol_payloads() {
		let msg = ProtocolMsg::BootGenesisResponse {
			nsm_response: NsmResponse::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 3,
				module_id: "module".to_string(),
				max_pcrs: 32,
				locked_pcrs: BTreeSet::from([0, 1, 2]),
				digest: qos_nsm::types::NsmDigest::SHA384,
			},
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

		let encoded = msg.to_json_wire().unwrap();
		let (decoded, encoding) = ProtocolMsg::from_wire(&encoded).unwrap();

		assert_eq!(encoding, ProtocolMsgEncoding::Json);
		assert_eq!(decoded, msg);
	}

	#[test]
	fn v2_manifest_envelope_is_json_wire_only() {
		let manifest = ManifestV2 {
			version: ManifestVersion::V2,
			namespace: Namespace {
				name: "test".to_string(),
				nonce: 1,
				quorum_key: vec![7; 33],
			},
			pivot: PivotConfigV2 {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				bridge_config: vec![],
				debug_mode: false,
				args: vec![],
				env: PivotEnv::new(),
			},
			manifest_set: ManifestSet { threshold: 1, members: vec![] },
			share_set: ShareSet { threshold: 1, members: vec![] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
		};
		let msg = ProtocolMsg::BootStandardRequest {
			manifest_envelope: Box::new(VersionedManifestEnvelope::V2(
				ManifestEnvelopeV2 {
					manifest,
					manifest_set_approvals: vec![],
					share_set_approvals: vec![],
				},
			)),
			pivot: vec![],
		};

		let encoded = msg.to_json_wire().unwrap();
		let (decoded, encoding) = ProtocolMsg::from_wire(&encoded).unwrap();

		assert_eq!(encoding, ProtocolMsgEncoding::Json);
		assert_eq!(decoded, msg);
		assert!(msg.to_borsh_wire().is_err());
	}

	#[test]
	fn boot_standard_json_envelope_request_is_borsh_only() {
		let envelope = VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest: ManifestV2 {
				version: ManifestVersion::V2,
				namespace: Namespace {
					name: "test".to_string(),
					nonce: 1,
					quorum_key: vec![7; 33],
				},
				pivot: PivotConfigV2 {
					hash: [9; 32],
					restart: RestartPolicy::Never,
					bridge_config: vec![],
					debug_mode: false,
					args: vec![],
					env: PivotEnv::new(),
				},
				manifest_set: ManifestSet { threshold: 1, members: vec![] },
				share_set: ShareSet { threshold: 1, members: vec![] },
				enclave: NitroConfig {
					pcr0: vec![0; 48],
					pcr1: vec![1; 48],
					pcr2: vec![2; 48],
					pcr3: vec![3; 48],
					aws_root_certificate: vec![],
					qos_commit: "commit".to_string(),
				},
			},
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		});
		let msg = ProtocolMsg::BootStandardJsonEnvelopeRequest {
			manifest_envelope: Box::new(JsonBytes::new(envelope)),
			pivot: vec![1, 2, 3, 4],
		};

		let encoded = msg.to_borsh_wire().unwrap();
		let (decoded, encoding) = ProtocolMsg::from_wire(&encoded).unwrap();

		assert_eq!(encoding, ProtocolMsgEncoding::Borsh);
		assert_eq!(decoded, msg);
		assert!(msg.to_json_wire().is_err());
	}
}
