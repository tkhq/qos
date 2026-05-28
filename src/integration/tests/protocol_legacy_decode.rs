#![cfg(feature = "legacy-protocol-compat")]

use borsh::BorshDeserialize;
use qos_core::protocol::{
	ProtocolError, ProtocolPhase,
	msg::ProtocolMsg as CurrentProtocolMsg,
	services::{
		boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, Namespace,
			NitroConfig, PatchSet, PivotConfig, QuorumMember, RestartPolicy,
			ShareSet,
		},
		genesis::{GenesisOutput, GenesisSet},
	},
};
use qos_core_legacy::protocol::{
	ProtocolError as LegacyProtocolError,
	msg::ProtocolMsg as LegacyProtocolMsg,
	services::boot::{
		Manifest as LegacyManifest, ManifestEnvelope as LegacyManifestEnvelope,
		ManifestEnvelopeV0 as LegacyManifestEnvelopeV0,
		ManifestV0 as LegacyManifestV0,
	},
};
use qos_nsm::types::NsmResponse;

fn sample_manifest() -> Manifest {
	Manifest {
		namespace: Namespace {
			name: "compat-ns".to_string(),
			nonce: 7,
			quorum_key: vec![9; 33],
		},
		enclave: NitroConfig {
			pcr0: vec![0; 48],
			pcr1: vec![1; 48],
			pcr2: vec![2; 48],
			pcr3: vec![3; 48],
			aws_root_certificate: vec![4; 16],
			qos_commit: "compat-commit".to_string(),
		},
		pivot: PivotConfig {
			hash: [7; 32],
			restart: RestartPolicy::Never,
			args: vec!["--flag".to_string(), "value".to_string()],
			bridge_config: vec![],
			debug_mode: false,
		},
		manifest_set: ManifestSet { threshold: 1, members: vec![] },
		share_set: ShareSet { threshold: 1, members: vec![] },
		patch_set: PatchSet { threshold: 0, members: vec![] },
	}
}

fn sample_approval() -> Approval {
	Approval {
		signature: vec![1, 2, 3, 4],
		member: qos_core::protocol::services::boot::QuorumMember {
			alias: "compat-member".to_string(),
			pub_key: vec![8; 33],
		},
	}
}

fn sample_manifest_envelope() -> ManifestEnvelope {
	ManifestEnvelope {
		manifest: sample_manifest(),
		manifest_set_approvals: vec![sample_approval()],
		share_set_approvals: vec![sample_approval()],
	}
}

fn sample_manifest_v0() -> qos_core::protocol::services::boot::ManifestV0 {
	qos_core::protocol::services::boot::ManifestV0 {
		namespace: Namespace {
			name: "compat-v0".to_string(),
			nonce: 11,
			quorum_key: vec![4; 33],
		},
		enclave: NitroConfig {
			pcr0: vec![0; 48],
			pcr1: vec![1; 48],
			pcr2: vec![2; 48],
			pcr3: vec![3; 48],
			aws_root_certificate: vec![1; 16],
			qos_commit: "compat-v0-commit".to_string(),
		},
		pivot: qos_core::protocol::services::boot::PivotConfigV0 {
			hash: [3; 32],
			restart: RestartPolicy::Always,
			args: vec!["v0arg".to_string()],
		},
		manifest_set: ManifestSet { threshold: 1, members: vec![] },
		share_set: ShareSet { threshold: 1, members: vec![] },
		patch_set: PatchSet { threshold: 0, members: vec![] },
	}
}

fn sample_manifest_envelope_v0()
-> qos_core::protocol::services::boot::ManifestEnvelopeV0 {
	qos_core::protocol::services::boot::ManifestEnvelopeV0 {
		manifest: sample_manifest_v0(),
		manifest_set_approvals: vec![sample_approval()],
		share_set_approvals: vec![sample_approval()],
	}
}

fn sample_genesis_output() -> GenesisOutput {
	GenesisOutput {
		quorum_key: vec![3, 2, 1],
		member_outputs: vec![],
		recovery_permutations: vec![],
		threshold: 2,
		dr_key_wrapped_quorum_key: None,
		quorum_key_hash: [22; 64],
		test_message_ciphertext: vec![5; 8],
		test_message_signature: vec![6; 8],
		test_message: vec![7; 8],
	}
}

fn sample_genesis_set() -> GenesisSet {
	GenesisSet {
		threshold: 2,
		members: vec![
			QuorumMember { alias: "a".to_string(), pub_key: vec![1; 33] },
			QuorumMember { alias: "b".to_string(), pub_key: vec![2; 33] },
		],
	}
}

fn decode_legacy(msg: CurrentProtocolMsg) -> LegacyProtocolMsg {
	let bytes = msg.to_borsh_wire().unwrap();
	LegacyProtocolMsg::try_from_slice(&bytes).unwrap()
}

#[test]
fn legacy_protocol_error_response_decodes() {
	let decoded = decode_legacy(CurrentProtocolMsg::ProtocolErrorResponse(
		ProtocolError::InvalidMsg,
	));
	assert!(matches!(decoded, LegacyProtocolMsg::ProtocolErrorResponse(_)));
}

#[test]
fn legacy_protocol_msg_deserialization_discriminant_is_stable() {
	let legacy = LegacyProtocolMsg::ProtocolErrorResponse(
		LegacyProtocolError::ProtocolMsgDeserialization,
	);
	let bytes = borsh::to_vec(&legacy).unwrap();
	let decoded = CurrentProtocolMsg::try_from_slice(&bytes).unwrap();

	assert!(matches!(
		decoded,
		CurrentProtocolMsg::ProtocolErrorResponse(
			ProtocolError::ProtocolMsgDeserialization
		)
	));
}

#[test]
fn legacy_status_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::StatusRequest);
	assert!(matches!(req, LegacyProtocolMsg::StatusRequest));

	let resp = decode_legacy(CurrentProtocolMsg::StatusResponse(
		ProtocolPhase::WaitingForBootInstruction,
	));
	assert!(matches!(resp, LegacyProtocolMsg::StatusResponse(_)));
}

#[test]
fn legacy_boot_standard_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::BootStandardRequest {
		manifest_envelope: Box::new(sample_manifest_envelope().into()),
		pivot: vec![1, 2, 3],
	});
	assert!(matches!(req, LegacyProtocolMsg::BootStandardRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::BootStandardResponse {
		nsm_response: NsmResponse::LockPCR,
	});
	assert!(matches!(resp, LegacyProtocolMsg::BootStandardResponse { .. }));
}

#[test]
fn legacy_boot_genesis_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::BootGenesisRequest {
		set: sample_genesis_set(),
		dr_key: Some(vec![5; 33]),
	});
	assert!(matches!(req, LegacyProtocolMsg::BootGenesisRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::BootGenesisResponse {
		nsm_response: NsmResponse::LockPCR,
		genesis_output: Box::new(sample_genesis_output()),
	});
	assert!(matches!(resp, LegacyProtocolMsg::BootGenesisResponse { .. }));
}

#[test]
fn legacy_provision_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::ProvisionRequest {
		share: vec![9; 32],
		approval: sample_approval(),
	});
	assert!(matches!(req, LegacyProtocolMsg::ProvisionRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::ProvisionResponse {
		reconstructed: true,
	});
	assert!(matches!(
		resp,
		LegacyProtocolMsg::ProvisionResponse { reconstructed: true }
	));
}

#[test]
fn legacy_proxy_variants_decode() {
	let req =
		decode_legacy(CurrentProtocolMsg::ProxyRequest { data: vec![1; 5] });
	assert!(matches!(req, LegacyProtocolMsg::ProxyRequest { .. }));

	let resp =
		decode_legacy(CurrentProtocolMsg::ProxyResponse { data: vec![2; 5] });
	assert!(matches!(resp, LegacyProtocolMsg::ProxyResponse { .. }));
}

#[test]
fn legacy_live_attestation_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::LiveAttestationDocRequest);
	assert!(matches!(req, LegacyProtocolMsg::LiveAttestationDocRequest));

	let resp = decode_legacy(CurrentProtocolMsg::LiveAttestationDocResponse {
		nsm_response: NsmResponse::LockPCR,
		manifest_envelope: Some(Box::new(sample_manifest_envelope().into())),
	});
	assert!(matches!(
		resp,
		LegacyProtocolMsg::LiveAttestationDocResponse { .. }
	));
}

#[test]
fn legacy_boot_key_forward_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::BootKeyForwardRequest {
		manifest_envelope: Box::new(sample_manifest_envelope().into()),
		pivot: vec![3, 2, 1],
	});
	assert!(matches!(req, LegacyProtocolMsg::BootKeyForwardRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::BootKeyForwardResponse {
		nsm_response: NsmResponse::LockPCR,
	});
	assert!(matches!(resp, LegacyProtocolMsg::BootKeyForwardResponse { .. }));
}

#[test]
fn legacy_export_key_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::ExportKeyRequest {
		manifest_envelope: Box::new(sample_manifest_envelope().into()),
		cose_sign1_attestation_doc: vec![7; 24],
	});
	assert!(matches!(req, LegacyProtocolMsg::ExportKeyRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::ExportKeyResponse {
		encrypted_quorum_key: vec![8; 33],
		signature: vec![9; 64],
	});
	assert!(matches!(resp, LegacyProtocolMsg::ExportKeyResponse { .. }));
}

#[test]
fn legacy_inject_key_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::InjectKeyRequest {
		encrypted_quorum_key: vec![4; 33],
		signature: vec![5; 64],
	});
	assert!(matches!(req, LegacyProtocolMsg::InjectKeyRequest { .. }));

	let resp = decode_legacy(CurrentProtocolMsg::InjectKeyResponse);
	assert!(matches!(resp, LegacyProtocolMsg::InjectKeyResponse));
}

#[test]
fn legacy_manifest_envelope_variants_decode() {
	let req = decode_legacy(CurrentProtocolMsg::ManifestEnvelopeRequest);
	assert!(matches!(req, LegacyProtocolMsg::ManifestEnvelopeRequest));

	let resp = decode_legacy(CurrentProtocolMsg::ManifestEnvelopeResponse {
		manifest_envelope: Box::new(Some(sample_manifest_envelope().into())),
	});
	assert!(matches!(resp, LegacyProtocolMsg::ManifestEnvelopeResponse { .. }));
}

#[test]
fn legacy_0_7_cannot_decode_post_0_7_protocol_variants() {
	let version_req =
		CurrentProtocolMsg::VersionRequest.to_borsh_wire().unwrap();
	assert!(LegacyProtocolMsg::try_from_slice(&version_req).is_err());

	let version_resp = CurrentProtocolMsg::VersionResponse {
		version: "0.7.0".to_string(),
		commit: "abcdef1".to_string(),
	}
	.to_borsh_wire()
	.unwrap();
	assert!(LegacyProtocolMsg::try_from_slice(&version_resp).is_err());

	let boot_json_envelope =
		CurrentProtocolMsg::BootStandardJsonEnvelopeRequest {
			manifest_envelope: Box::new(
				qos_core::protocol::msg::JsonBytes::new(
					sample_manifest_envelope().into(),
				),
			),
			pivot: vec![1, 2, 3],
		}
		.to_borsh_wire()
		.unwrap();
	assert!(LegacyProtocolMsg::try_from_slice(&boot_json_envelope).is_err());
}

#[test]
fn legacy_manifest_decodes_current_manifest_v1_borsh() {
	let manifest = sample_manifest();
	let bytes = borsh::to_vec(&manifest).unwrap();
	let decoded = LegacyManifest::try_from_slice(&bytes).unwrap();
	assert_eq!(decoded.namespace.name, "compat-ns");
	assert_eq!(decoded.namespace.nonce, 7);
	assert_eq!(decoded.pivot.args, vec!["--flag", "value"]);
}

#[test]
fn legacy_manifest_envelope_decodes_current_envelope_v1_borsh() {
	let envelope = sample_manifest_envelope();
	let bytes = borsh::to_vec(&envelope).unwrap();
	let decoded = LegacyManifestEnvelope::try_from_slice(&bytes).unwrap();
	assert_eq!(decoded.manifest.namespace.name, "compat-ns");
	assert_eq!(decoded.manifest_set_approvals.len(), 1);
	assert_eq!(decoded.share_set_approvals.len(), 1);
}

#[test]
fn legacy_manifest_v0_decodes_current_manifest_v0_borsh() {
	let manifest_v0 = sample_manifest_v0();
	let bytes = borsh::to_vec(&manifest_v0).unwrap();
	let decoded = LegacyManifestV0::try_from_slice(&bytes).unwrap();
	assert_eq!(decoded.namespace.name, "compat-v0");
	assert_eq!(decoded.namespace.nonce, 11);
	assert_eq!(decoded.pivot.args, vec!["v0arg"]);
}

#[test]
fn legacy_manifest_envelope_v0_decodes_current_envelope_v0_borsh() {
	let envelope_v0 = sample_manifest_envelope_v0();
	let bytes = borsh::to_vec(&envelope_v0).unwrap();
	let decoded = LegacyManifestEnvelopeV0::try_from_slice(&bytes).unwrap();
	assert_eq!(decoded.manifest.namespace.name, "compat-v0");
	assert_eq!(decoded.manifest_set_approvals.len(), 1);
	assert_eq!(decoded.share_set_approvals.len(), 1);
}
