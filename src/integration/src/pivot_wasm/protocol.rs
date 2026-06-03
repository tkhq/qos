//! Protocol types for the WASM meta-pivot demo.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::protocol::services::boot::{Approval, ManifestSet};
use qos_crypto::sha_256;

pub const PIVOT_WASM_ABI_VERSION: u32 = 1;

#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Hash,
)]
pub enum PivotWasmArtifactKind {
	Function,
	Policy,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmArtifact {
	pub kind: PivotWasmArtifactKind,
	pub name: String,
	pub version: String,
	pub wasm_hash: [u8; 32],
	pub abi_version: u32,
	pub metadata_hash: [u8; 32],
}

impl PivotWasmArtifact {
	pub fn new(
		kind: PivotWasmArtifactKind,
		name: impl Into<String>,
		version: impl Into<String>,
		wasm: &[u8],
		metadata: &[u8],
	) -> Self {
		Self {
			kind,
			name: name.into(),
			version: version.into(),
			wasm_hash: sha_256(wasm),
			abi_version: PIVOT_WASM_ABI_VERSION,
			metadata_hash: sha_256(metadata),
		}
	}

	pub fn approval_payload_hash(&self) -> [u8; 32] {
		sha_256(&borsh::to_vec(self).expect("artifact serializes"))
	}
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmArtifactEnvelope {
	pub artifact: PivotWasmArtifact,
	pub approvals: Vec<Approval>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmGovernance {
	pub artifact_set: ManifestSet,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmRegisterArtifactRequest {
	pub envelope: PivotWasmArtifactEnvelope,
	pub wasm: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmRegisterArtifactResponse {
	pub artifact: PivotWasmArtifact,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmRegisteredArtifact {
	pub artifact: PivotWasmArtifact,
	pub approval_count: u32,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmExecuteRequest {
	pub policy_hash: [u8; 32],
	pub function_hash: [u8; 32],
	pub input: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmExecuteResponse {
	pub output: Vec<u8>,
	pub attestation: PivotWasmExecutionAttestation,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmExecutionAttestationPayload {
	pub engine_id: [u8; 32],
	pub policy_hash: [u8; 32],
	pub function_hash: [u8; 32],
	pub input_hash: [u8; 32],
	pub output_hash: [u8; 32],
	pub abi_version: u32,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PivotWasmExecutionAttestation {
	pub payload: PivotWasmExecutionAttestationPayload,
	pub signature: Vec<u8>,
	pub public_key: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub enum PivotWasmMsg {
	RegisterArtifactRequest(PivotWasmRegisterArtifactRequest),
	RegisterArtifactResponse(PivotWasmRegisterArtifactResponse),
	ListArtifactsRequest,
	ListArtifactsResponse { artifacts: Vec<PivotWasmRegisteredArtifact> },
	ExecuteRequest(PivotWasmExecuteRequest),
	ExecuteResponse(PivotWasmExecuteResponse),
	PolicyDenied { reason: String },
	InvalidApproval { message: String },
	RuntimeError { message: String },
}
