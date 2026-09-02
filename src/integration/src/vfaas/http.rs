//! JSON DTOs for the pivot's HTTP front, shared by the server
//! (`pivot_vfaas`) and its clients (the xtask, the demo site).
//!
//! Conventions: every binary field is a lowercase hex string. Signed
//! governance blobs ([`ArtifactEnvelope`], [`RulesetEnvelope`]) travel as
//! hex-encoded *Borsh* — the exact bytes the quorum approved — so JSON
//! round-tripping can never disturb a signature. Program input/output are
//! hex-encoded Borsh of the program's typed contract, byte-for-byte what
//! the attestation hashes commit to.

use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use vfaas_abi::{
	ExecutionAttestation, ExecutionAttestationPayload, ExecutionOutcome, Stage,
};

use super::{
	RegisteredArtifact, VfaasMsg,
	governance::{ArtifactEnvelope, ArtifactKind, RulesetEnvelope},
};

/// `GET /health` response. Doubles as the TVC health probe and the replica
/// identity check: `replica` is the first 8 hex chars of this enclave's
/// ephemeral public key, unique per replica.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Health {
	/// Always `"healthy"` when the pivot is serving.
	pub status: String,
	/// Replica fingerprint; `None` if the ephemeral key is unreadable.
	pub replica: Option<String>,
}

/// One registered artifact, as reported by `GET /artifacts`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSummary {
	/// Human-readable artifact name.
	pub name: String,
	/// Artifact version string.
	pub version: String,
	/// `"function"` or `"policy"`.
	pub kind: String,
	/// SHA-256 of the WASM blob, hex — the content address used by
	/// `POST /f/{wasmHash}`.
	pub wasm_hash: String,
	/// Guest ABI version the artifact targets.
	pub abi_version: u32,
	/// Approved per-execution fuel budget; `None` means the engine default.
	pub fuel_budget: Option<u64>,
	/// How many quorum approvals the registered envelope carried.
	pub approval_count: u32,
	/// For functions: hex hash of the quorum-bound gating policy.
	pub bound_policy: Option<String>,
}

impl From<&RegisteredArtifact> for ArtifactSummary {
	fn from(registered: &RegisteredArtifact) -> Self {
		let artifact = &registered.artifact;

		Self {
			name: artifact.name.clone(),
			version: artifact.version.clone(),
			kind: match artifact.kind {
				ArtifactKind::Function => "function".to_string(),
				ArtifactKind::Policy => "policy".to_string(),
			},
			wasm_hash: qos_hex::encode(&artifact.wasm_hash),
			abi_version: artifact.abi_version,
			fuel_budget: artifact.fuel_budget,
			approval_count: registered.approval_count,
			bound_policy: registered
				.bound_policy
				.map(|policy| qos_hex::encode(policy.as_bytes())),
		}
	}
}

/// `GET /artifacts` response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Artifacts {
	/// Fingerprint of the replica that answered.
	pub replica: Option<String>,
	/// Registered artifacts, sorted by name then version.
	pub artifacts: Vec<ArtifactSummary>,
}

/// `POST /artifacts` request: a quorum-approved artifact registration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
	/// Hex-encoded Borsh [`ArtifactEnvelope`] — the exact signed bytes.
	pub envelope: String,
	/// Hex-encoded WASM blob; must hash to the envelope's `wasm_hash`.
	pub wasm: String,
	/// Hex-encoded Borsh [`RulesetEnvelope`]; required for functions,
	/// absent for policies.
	pub ruleset: Option<String>,
}

impl RegisterRequest {
	/// Parse into the wire message, decoding hex and the signed Borsh
	/// envelopes.
	///
	/// # Errors
	///
	/// Returns a description of the first field that failed to decode.
	pub fn into_msg(self) -> Result<VfaasMsg, String> {
		let envelope_bytes = qos_hex::decode(&self.envelope)
			.map_err(|e| format!("envelope is not hex: {e:?}"))?;
		let envelope = ArtifactEnvelope::try_from_slice(&envelope_bytes)
			.map_err(|e| {
				format!("envelope is not a Borsh ArtifactEnvelope: {e}")
			})?;
		let wasm = qos_hex::decode(&self.wasm)
			.map_err(|e| format!("wasm is not hex: {e:?}"))?;
		let ruleset = self
			.ruleset
			.as_deref()
			.map(|hex| {
				let bytes = qos_hex::decode(hex)
					.map_err(|e| format!("ruleset is not hex: {e:?}"))?;
				RulesetEnvelope::try_from_slice(&bytes).map_err(|e| {
					format!("ruleset is not a Borsh RulesetEnvelope: {e}")
				})
			})
			.transpose()?;

		Ok(VfaasMsg::RegisterArtifactRequest { envelope, wasm, ruleset })
	}
}

/// `POST /artifacts` success response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Registered {
	/// Fingerprint of the replica that accepted the registration — the
	/// saturate-register loop counts distinct values of this field.
	pub replica: Option<String>,
	/// Registered artifact name.
	pub name: String,
	/// Registered artifact version.
	pub version: String,
	/// The artifact's content address, hex.
	pub wasm_hash: String,
}

/// `POST /f/{wasmHash}` request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExecuteRequest {
	/// Hex-encoded Borsh of the program's typed input.
	pub input: String,
}

/// `POST /f/{wasmHash}` response. Allowed, denied, and failed outcomes all
/// arrive here with HTTP 200 — they are attested execution outcomes, not
/// transport errors.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Execution {
	/// Hex-encoded program output when the outcome is allowed.
	pub output: Option<String>,
	/// The enclave-signed record of the attempt.
	pub attestation: Attestation,
}

/// An [`ExecutionAttestation`] rendered for JSON clients. `payload` is the
/// decoded view; `payload_borsh` is the exact byte string the signature
/// covers, so verifying needs no Borsh re-implementation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
	/// Decoded attestation payload.
	pub payload: AttestationPayload,
	/// Hex-encoded Borsh of the payload — the signed bytes.
	pub payload_borsh: String,
	/// Hex-encoded P-256 signature over `payload_borsh`.
	pub signature: String,
	/// Hex-encoded enclave ephemeral public key (encrypt ‖ sign halves).
	pub ephemeral_public_key: String,
}

impl From<&ExecutionAttestation> for Attestation {
	fn from(signed: &ExecutionAttestation) -> Self {
		let payload_borsh =
			borsh::to_vec(&signed.payload).expect("payload serializes");

		Self {
			payload: AttestationPayload::from(&signed.payload),
			payload_borsh: qos_hex::encode(&payload_borsh),
			signature: qos_hex::encode(&signed.signature),
			ephemeral_public_key: qos_hex::encode(&signed.ephemeral_public_key),
		}
	}
}

/// Decoded [`ExecutionAttestationPayload`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationPayload {
	/// Identity of the engine build, hex.
	pub engine_id: String,
	/// Guest ABI version the engine spoke.
	pub abi_version: u32,
	/// Content address of the program that ran, hex.
	pub program_hash: String,
	/// Content address of the quorum-bound policy that gated it, hex.
	pub policy_hash: String,
	/// SHA-256 of the input bytes, hex.
	pub input_hash: String,
	/// What happened.
	pub outcome: Outcome,
	/// Monotonic per-pivot request counter.
	pub request_id: u64,
}

impl From<&ExecutionAttestationPayload> for AttestationPayload {
	fn from(payload: &ExecutionAttestationPayload) -> Self {
		Self {
			engine_id: qos_hex::encode(&payload.engine_id),
			abi_version: payload.abi_version,
			program_hash: qos_hex::encode(payload.program_hash.as_bytes()),
			policy_hash: qos_hex::encode(payload.policy_hash.as_bytes()),
			input_hash: qos_hex::encode(&payload.input_hash),
			outcome: Outcome::from(&payload.outcome),
			request_id: payload.request_id,
		}
	}
}

/// Decoded [`ExecutionOutcome`], tagged by `status`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(
	tag = "status",
	rename_all = "camelCase",
	rename_all_fields = "camelCase"
)]
pub enum Outcome {
	/// The policy allowed the run and the program completed.
	Allowed {
		/// SHA-256 of the output bytes, hex.
		output_hash: String,
	},
	/// The quorum-bound policy denied the run.
	Denied {
		/// The policy's stated reason.
		reason: String,
	},
	/// The policy or program itself failed (trap, fuel exhaustion, ABI
	/// violation).
	Failed {
		/// `"policy"` or `"program"`.
		stage: String,
		/// The failure, with its cause chain.
		reason: String,
	},
}

impl From<&ExecutionOutcome> for Outcome {
	fn from(outcome: &ExecutionOutcome) -> Self {
		match outcome {
			ExecutionOutcome::Allowed { output_hash } => {
				Self::Allowed { output_hash: qos_hex::encode(output_hash) }
			}
			ExecutionOutcome::Denied { reason } => {
				Self::Denied { reason: reason.clone() }
			}
			ExecutionOutcome::Failed { stage, reason } => Self::Failed {
				stage: match stage {
					Stage::Policy => "policy".to_string(),
					Stage::Program => "program".to_string(),
				},
				reason: reason.clone(),
			},
		}
	}
}

/// Error body for non-2xx responses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Error {
	/// What the pivot rejected.
	pub error: String,
}
