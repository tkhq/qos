//! In-memory registry of signed WASM artifacts.

use std::collections::HashMap;

use qos_core::protocol::services::boot::ManifestSet;
use qos_crypto::sha_256;

use super::{
	approvals::verify_artifact_envelope,
	errors::PivotWasmError,
	protocol::{
		PivotWasmArtifact, PivotWasmArtifactEnvelope, PivotWasmArtifactKind,
		PivotWasmGovernance, PivotWasmRegisterArtifactRequest,
		PivotWasmRegisterArtifactResponse, PivotWasmRegisteredArtifact,
	},
};

#[derive(Clone)]
struct StoredArtifact {
	envelope: PivotWasmArtifactEnvelope,
	wasm: Vec<u8>,
}

pub struct WasmRegistry {
	artifact_set: ManifestSet,
	artifacts: HashMap<[u8; 32], StoredArtifact>,
}

impl WasmRegistry {
	pub fn new(governance: PivotWasmGovernance) -> Self {
		Self {
			artifact_set: governance.artifact_set,
			artifacts: HashMap::new(),
		}
	}

	pub fn register(
		&mut self,
		request: PivotWasmRegisterArtifactRequest,
	) -> Result<PivotWasmRegisterArtifactResponse, PivotWasmError> {
		let actual_hash = sha_256(&request.wasm);
		if actual_hash != request.envelope.artifact.wasm_hash {
			return Err(PivotWasmError::Approval(format!(
				"artifact hash mismatch for {}",
				request.envelope.artifact.name
			)));
		}

		verify_artifact_envelope(&request.envelope, &self.artifact_set)?;

		let artifact = request.envelope.artifact.clone();
		self.artifacts.insert(
			artifact.wasm_hash,
			StoredArtifact { envelope: request.envelope, wasm: request.wasm },
		);

		Ok(PivotWasmRegisterArtifactResponse { artifact })
	}

	pub fn list(&self) -> Vec<PivotWasmRegisteredArtifact> {
		let mut artifacts: Vec<_> = self
			.artifacts
			.values()
			.map(|stored| PivotWasmRegisteredArtifact {
				artifact: stored.envelope.artifact.clone(),
				approval_count: stored.envelope.approvals.len() as u32,
			})
			.collect();
		artifacts.sort_by(|a, b| {
			a.artifact
				.name
				.cmp(&b.artifact.name)
				.then(a.artifact.version.cmp(&b.artifact.version))
		});
		artifacts
	}

	pub fn function_bytes(
		&self,
		hash: &[u8; 32],
	) -> Result<(PivotWasmArtifact, Vec<u8>), PivotWasmError> {
		self.artifact_bytes(hash, PivotWasmArtifactKind::Function)
	}

	pub fn policy_bytes(
		&self,
		hash: &[u8; 32],
	) -> Result<(PivotWasmArtifact, Vec<u8>), PivotWasmError> {
		self.artifact_bytes(hash, PivotWasmArtifactKind::Policy)
	}

	fn artifact_bytes(
		&self,
		hash: &[u8; 32],
		expected_kind: PivotWasmArtifactKind,
	) -> Result<(PivotWasmArtifact, Vec<u8>), PivotWasmError> {
		let stored = self.artifacts.get(hash).ok_or_else(|| {
			PivotWasmError::NotFound(format!(
				"artifact not registered: {}",
				qos_hex::encode(hash)
			))
		})?;
		if stored.envelope.artifact.kind != expected_kind {
			return Err(PivotWasmError::NotFound(format!(
				"artifact {} is not a {:?}",
				stored.envelope.artifact.name, expected_kind
			)));
		}
		Ok((stored.envelope.artifact.clone(), stored.wasm.clone()))
	}
}
