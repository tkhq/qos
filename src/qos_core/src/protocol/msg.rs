//! Enclave executor message types.
//!
//! These types are re-exported from [`qos_proto`] for wire format encoding.
//! The protocol uses protobuf encoding for cross-language interoperability.

// Re-export proto types for protocol messages
pub use qos_proto::{
	protocol_msg, BootGenesisRequest, BootGenesisResponse, BootKeyForwardRequest,
	BootKeyForwardResponse, BootStandardRequest, BootStandardResponse,
	ExportKeyRequest, ExportKeyResponse, InjectKeyRequest, InjectKeyResponse,
	LiveAttestationDocRequest, LiveAttestationDocResponse, ManifestEnvelopeRequest,
	ManifestEnvelopeResponse, ProtocolMsg, ProvisionRequest, ProvisionResponse,
	ProxyRequest, ProxyResponse, StatusRequest, StatusResponse,
};

/// Extension trait for constructing ProtocolMsg variants.
pub trait ProtocolMsgExt {
	/// Create an error response.
	fn error_response(error: qos_proto::ProtocolError) -> ProtocolMsg {
		ProtocolMsg { msg: Some(protocol_msg::Msg::ErrorResponse(error)) }
	}

	/// Create a status request.
	fn status_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::StatusRequest(StatusRequest {})),
		}
	}

	/// Create a status response.
	fn status_response(phase: qos_proto::ProtocolPhase) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::StatusResponse(StatusResponse {
				phase: phase as i32,
			})),
		}
	}

	/// Create a boot standard request.
	fn boot_standard_request(
		manifest_envelope: qos_proto::ManifestEnvelope,
		pivot: Vec<u8>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootStandardRequest(
				BootStandardRequest {
					manifest_envelope: Some(manifest_envelope),
					pivot,
				},
			)),
		}
	}

	/// Create a boot standard response.
	fn boot_standard_response(nsm_response: qos_proto::NsmResponse) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootStandardResponse(
				BootStandardResponse { nsm_response: Some(nsm_response) },
			)),
		}
	}

	/// Create a boot genesis request.
	fn boot_genesis_request(
		set: qos_proto::GenesisSet,
		dr_key: Option<Vec<u8>>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootGenesisRequest(BootGenesisRequest {
				set: Some(set),
				dr_key,
			})),
		}
	}

	/// Create a boot genesis response.
	fn boot_genesis_response(
		nsm_response: qos_proto::NsmResponse,
		genesis_output: qos_proto::GenesisOutput,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootGenesisResponse(
				BootGenesisResponse {
					nsm_response: Some(nsm_response),
					genesis_output: Some(genesis_output),
				},
			)),
		}
	}

	/// Create a boot key forward request.
	fn boot_key_forward_request(
		manifest_envelope: qos_proto::ManifestEnvelope,
		pivot: Vec<u8>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootKeyForwardRequest(
				BootKeyForwardRequest {
					manifest_envelope: Some(manifest_envelope),
					pivot,
				},
			)),
		}
	}

	/// Create a boot key forward response.
	fn boot_key_forward_response(
		nsm_response: qos_proto::NsmResponse,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootKeyForwardResponse(
				BootKeyForwardResponse { nsm_response: Some(nsm_response) },
			)),
		}
	}

	/// Create a provision request.
	fn provision_request(
		share: Vec<u8>,
		approval: qos_proto::Approval,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProvisionRequest(ProvisionRequest {
				share,
				approval: Some(approval),
			})),
		}
	}

	/// Create a provision response.
	fn provision_response(reconstructed: bool) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProvisionResponse(ProvisionResponse {
				reconstructed,
			})),
		}
	}

	/// Create a proxy request.
	fn proxy_request(data: Vec<u8>) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProxyRequest(ProxyRequest { data })),
		}
	}

	/// Create a proxy response.
	fn proxy_response(data: Vec<u8>) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProxyResponse(ProxyResponse { data })),
		}
	}

	/// Create a live attestation doc request.
	fn live_attestation_doc_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::LiveAttestationDocRequest(
				LiveAttestationDocRequest {},
			)),
		}
	}

	/// Create a live attestation doc response.
	fn live_attestation_doc_response(
		nsm_response: qos_proto::NsmResponse,
		manifest_envelope: Option<qos_proto::ManifestEnvelope>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::LiveAttestationDocResponse(
				LiveAttestationDocResponse { nsm_response: Some(nsm_response), manifest_envelope },
			)),
		}
	}

	/// Create an export key request.
	fn export_key_request(
		manifest_envelope: qos_proto::ManifestEnvelope,
		cose_sign1_attestation_doc: Vec<u8>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ExportKeyRequest(ExportKeyRequest {
				manifest_envelope: Some(manifest_envelope),
				cose_sign1_attestation_doc,
			})),
		}
	}

	/// Create an export key response.
	fn export_key_response(
		encrypted_quorum_key: Vec<u8>,
		signature: Vec<u8>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ExportKeyResponse(ExportKeyResponse {
				encrypted_quorum_key,
				signature,
			})),
		}
	}

	/// Create an inject key request.
	fn inject_key_request(
		encrypted_quorum_key: Vec<u8>,
		signature: Vec<u8>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::InjectKeyRequest(InjectKeyRequest {
				encrypted_quorum_key,
				signature,
			})),
		}
	}

	/// Create an inject key response.
	fn inject_key_response() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::InjectKeyResponse(InjectKeyResponse {})),
		}
	}

	/// Create a manifest envelope request.
	fn manifest_envelope_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ManifestEnvelopeRequest(
				ManifestEnvelopeRequest {},
			)),
		}
	}

	/// Create a manifest envelope response.
	fn manifest_envelope_response(
		manifest_envelope: Option<qos_proto::ManifestEnvelope>,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ManifestEnvelopeResponse(
				ManifestEnvelopeResponse { manifest_envelope },
			)),
		}
	}

}

impl ProtocolMsgExt for ProtocolMsg {}

/// Get a display name for a ProtocolMsg.
pub fn protocol_msg_name(msg: &ProtocolMsg) -> &'static str {
	match &msg.msg {
		None => "ProtocolMsg(empty)",
		Some(inner) => match inner {
			protocol_msg::Msg::ErrorResponse(_) => "ProtocolErrorResponse",
			protocol_msg::Msg::StatusRequest(_) => "StatusRequest",
			protocol_msg::Msg::StatusResponse(_) => "StatusResponse",
			protocol_msg::Msg::BootStandardRequest(_) => "BootStandardRequest",
			protocol_msg::Msg::BootStandardResponse(_) => "BootStandardResponse",
			protocol_msg::Msg::BootGenesisRequest(_) => "BootGenesisRequest",
			protocol_msg::Msg::BootGenesisResponse(_) => "BootGenesisResponse",
			protocol_msg::Msg::BootKeyForwardRequest(_) => "BootKeyForwardRequest",
			protocol_msg::Msg::BootKeyForwardResponse(_) => "BootKeyForwardResponse",
			protocol_msg::Msg::ProvisionRequest(_) => "ProvisionRequest",
			protocol_msg::Msg::ProvisionResponse(_) => "ProvisionResponse",
			protocol_msg::Msg::ProxyRequest(_) => "ProxyRequest",
			protocol_msg::Msg::ProxyResponse(_) => "ProxyResponse",
			protocol_msg::Msg::LiveAttestationDocRequest(_) => {
				"LiveAttestationDocRequest"
			}
			protocol_msg::Msg::LiveAttestationDocResponse(_) => {
				"LiveAttestationDocResponse"
			}
			protocol_msg::Msg::ExportKeyRequest(_) => "ExportKeyRequest",
			protocol_msg::Msg::ExportKeyResponse(_) => "ExportKeyResponse",
			protocol_msg::Msg::InjectKeyRequest(_) => "InjectKeyRequest",
			protocol_msg::Msg::InjectKeyResponse(_) => "InjectKeyResponse",
			protocol_msg::Msg::ManifestEnvelopeRequest(_) => {
				"ManifestEnvelopeRequest"
			}
			protocol_msg::Msg::ManifestEnvelopeResponse(_) => {
				"ManifestEnvelopeResponse"
			}
		},
	}
}
