//! Enclave executor message types.

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
	fn error_response(error: qos_proto::ProtocolError) -> ProtocolMsg {
		ProtocolMsg { msg: Some(protocol_msg::Msg::ErrorResponse(error)) }
	}

	fn status_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::StatusRequest(StatusRequest {})),
		}
	}

	fn status_response(phase: qos_proto::ProtocolPhase) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::StatusResponse(StatusResponse {
				phase: phase as i32,
			})),
		}
	}

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

	fn boot_standard_response(nsm_response: qos_proto::NsmResponse) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootStandardResponse(
				BootStandardResponse { nsm_response: Some(nsm_response) },
			)),
		}
	}

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

	fn boot_key_forward_response(
		nsm_response: qos_proto::NsmResponse,
	) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::BootKeyForwardResponse(
				BootKeyForwardResponse { nsm_response: Some(nsm_response) },
			)),
		}
	}

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

	fn provision_response(reconstructed: bool) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProvisionResponse(ProvisionResponse {
				reconstructed,
			})),
		}
	}

	fn proxy_request(data: Vec<u8>) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProxyRequest(ProxyRequest { data })),
		}
	}

	fn proxy_response(data: Vec<u8>) -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ProxyResponse(ProxyResponse { data })),
		}
	}

	fn live_attestation_doc_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::LiveAttestationDocRequest(
				LiveAttestationDocRequest {},
			)),
		}
	}

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

	fn inject_key_response() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::InjectKeyResponse(InjectKeyResponse {})),
		}
	}

	fn manifest_envelope_request() -> ProtocolMsg {
		ProtocolMsg {
			msg: Some(protocol_msg::Msg::ManifestEnvelopeRequest(
				ManifestEnvelopeRequest {},
			)),
		}
	}

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
