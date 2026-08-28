#![cfg(feature = "legacy-protocol-compat")]

use qos_core::protocol::{ProtocolError, ProtocolPhase, msg::ProtocolMsg};
use qos_nsm::types::NsmResponse;

/// Protocol v0.7 used these exact Borsh enum tags. This golden test avoids a
/// second, resolver-incompatible copy of old `qos_core` while still preventing
/// insertion or reordering of legacy wire variants.
#[test]
fn legacy_borsh_discriminants_remain_stable() {
	let cases = [
		(ProtocolMsg::ProtocolErrorResponse(ProtocolError::InvalidMsg), 0),
		(ProtocolMsg::StatusRequest, 1),
		(
			ProtocolMsg::StatusResponse(
				ProtocolPhase::WaitingForBootInstruction,
			),
			2,
		),
		(
			ProtocolMsg::BootStandardResponse {
				nsm_response: NsmResponse::LockPCR,
			},
			4,
		),
		(ProtocolMsg::ProvisionResponse { reconstructed: true }, 8),
		(ProtocolMsg::ProxyRequest { data: vec![] }, 9),
		(ProtocolMsg::ProxyResponse { data: vec![] }, 10),
		(ProtocolMsg::LiveAttestationDocRequest, 11),
		(
			ProtocolMsg::BootKeyForwardResponse {
				nsm_response: NsmResponse::LockPCR,
			},
			14,
		),
		(
			ProtocolMsg::ExportKeyResponse {
				encrypted_quorum_key: vec![],
				signature: vec![],
			},
			16,
		),
		(
			ProtocolMsg::InjectKeyRequest {
				encrypted_quorum_key: vec![],
				signature: vec![],
			},
			17,
		),
		(ProtocolMsg::InjectKeyResponse, 18),
		(ProtocolMsg::ManifestEnvelopeRequest, 19),
	];

	for (message, expected) in cases {
		assert_eq!(borsh::to_vec(&message).unwrap()[0], expected);
	}
}

#[test]
fn oci_variants_are_appended_after_existing_wire_variants() {
	assert_eq!(borsh::to_vec(&ProtocolMsg::VersionRequest).unwrap()[0], 21);
	assert_eq!(borsh::to_vec(&ProtocolMsg::OciStatusRequest).unwrap()[0], 26);
}
