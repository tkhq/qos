//! Verifiable Functions as a Service (vfaas): wire protocol and host-side
//! helpers for `pivot_vfaas`.
//!
//! The pivot holds an in-memory registry of quorum-approved WASM artifacts
//! (programs and policies). Registering an artifact requires an
//! [`governance::ArtifactEnvelope`] that verifies against the `ManifestSet`
//! the pivot was launched with. Execute runs the policy first and the
//! program only on `Allow`, and signs an [`ExecutionAttestation`] with the
//! enclave ephemeral key on every path — allowed, denied, or failed.
//!
//! Guest/host shared types live in the `vfaas-abi` crate; this module owns
//! the socket protocol and the client-side verification helpers.

pub mod governance;

use borsh::{BorshDeserialize, BorshSerialize};
use qos_crypto::sha_256;
use qos_p256::{P256Error, P256Public};
use vfaas_abi::{
	ExecutionAttestation, PolicyHash, ProgramHash, VFAAS_ABI_VERSION,
};

use governance::{Artifact, ArtifactEnvelope};

/// Default fuel budget for one WASM call when the artifact descriptor does
/// not carry its own [`governance::Artifact::fuel_budget`].
pub const DEFAULT_FUEL_PER_CALL: u64 = 1_000_000;

/// Identity of the vfaas execution engine build, bound into every
/// attestation payload.
#[must_use]
pub fn engine_id() -> [u8; 32] {
	sha_256(b"vfaas-engine-v1")
}

/// A registered artifact as reported by `ListArtifacts`.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct RegisteredArtifact {
	/// The approved descriptor.
	pub artifact: Artifact,
	/// How many approvals the registered envelope carried.
	pub approval_count: u32,
}

/// Request/response messages for the `pivot_vfaas` app.
///
/// Input/output convention: `ExecuteRequest.input` is the Borsh encoding of
/// the program's typed input, passed to the guest byte-for-byte; the
/// response `output` is the Borsh encoding of the program's typed output,
/// exactly the bytes the attestation's `output_hash` commits to. The pivot
/// never re-encodes either side.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub enum VfaasMsg {
	/// Register a quorum-approved WASM artifact.
	RegisterArtifactRequest {
		/// Descriptor plus quorum approvals.
		envelope: ArtifactEnvelope,
		/// The WASM blob; must hash to `envelope.artifact.wasm_hash`.
		wasm: Vec<u8>,
	},
	/// Success response to [`Self::RegisterArtifactRequest`].
	RegisterArtifactResponse {
		/// The descriptor as registered.
		artifact: Artifact,
	},
	/// List all registered artifacts.
	ListArtifactsRequest,
	/// Response to [`Self::ListArtifactsRequest`].
	ListArtifactsResponse {
		/// Registered artifacts, sorted by name then version.
		artifacts: Vec<RegisteredArtifact>,
	},
	/// Execute a registered program gated by a registered policy.
	ExecuteRequest {
		/// Hash of the program artifact to run.
		program: ProgramHash,
		/// Hash of the policy artifact gating the run.
		policy: PolicyHash,
		/// Borsh encoding of the program's typed input.
		input: Vec<u8>,
	},
	/// Response to [`Self::ExecuteRequest`]. The outcome (allowed, denied,
	/// or failed) lives inside the signed attestation payload — there is no
	/// unsigned copy to drift from it.
	ExecuteResponse {
		/// Program output bytes when the outcome is `Allowed`; `None`
		/// otherwise.
		output: Option<Vec<u8>>,
		/// Enclave-signed record of the attempt.
		attestation: ExecutionAttestation,
	},
	/// Request-level error (malformed message, unknown artifact, …). No
	/// execution was attempted, so nothing is attested.
	Error(String),
}

/// Why client-side attestation verification failed.
#[derive(Debug)]
pub enum AttestationVerifyError {
	/// The embedded ephemeral public key could not be parsed.
	BadEphemeralKey(P256Error),
	/// The payload failed to Borsh-serialize.
	SerializationFailed(std::io::Error),
	/// The signature does not verify over the payload.
	BadSignature(P256Error),
	/// The payload's engine id is not the expected vfaas engine.
	UnexpectedEngine,
	/// The payload's ABI version is not [`VFAAS_ABI_VERSION`].
	UnexpectedAbiVersion(u32),
}

/// Verify an [`ExecutionAttestation`] against its embedded ephemeral public
/// key, and check the payload names the expected engine and ABI version.
///
/// This is the canonical client-side check: anyone holding the attestation
/// can confirm the statement was signed by the holder of the referenced
/// ephemeral key. Tying that key to a hardware attestation document (NSM)
/// is the next layer up and is left to the caller.
///
/// # Errors
///
/// Returns an [`AttestationVerifyError`] naming the check that failed.
pub fn verify_execution_attestation(
	signed: &ExecutionAttestation,
) -> Result<(), AttestationVerifyError> {
	let pubkey = P256Public::from_bytes(&signed.ephemeral_public_key)
		.map_err(AttestationVerifyError::BadEphemeralKey)?;
	let payload = borsh::to_vec(&signed.payload)
		.map_err(AttestationVerifyError::SerializationFailed)?;
	pubkey
		.verify(&payload, &signed.signature)
		.map_err(AttestationVerifyError::BadSignature)?;

	if signed.payload.engine_id != engine_id() {
		return Err(AttestationVerifyError::UnexpectedEngine);
	}
	if signed.payload.abi_version != VFAAS_ABI_VERSION {
		return Err(AttestationVerifyError::UnexpectedAbiVersion(
			signed.payload.abi_version,
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use qos_p256::P256Pair;
	use vfaas_abi::{ExecutionAttestationPayload, ExecutionOutcome};

	use super::*;

	fn signed_attestation(pair: &P256Pair) -> ExecutionAttestation {
		let payload = ExecutionAttestationPayload {
			engine_id: engine_id(),
			abi_version: VFAAS_ABI_VERSION,
			program_hash: ProgramHash::new([1u8; 32]),
			policy_hash: PolicyHash::new([2u8; 32]),
			input_hash: [3u8; 32],
			outcome: ExecutionOutcome::Denied { reason: "test".into() },
			request_id: 7,
		};
		let bytes = borsh::to_vec(&payload).unwrap();
		ExecutionAttestation {
			payload,
			signature: pair.sign(&bytes).unwrap(),
			ephemeral_public_key: pair.public_key().to_bytes(),
		}
	}

	#[test]
	fn valid_attestation_verifies() {
		let pair = P256Pair::generate().unwrap();
		let signed = signed_attestation(&pair);
		assert!(verify_execution_attestation(&signed).is_ok());
	}

	#[test]
	fn tampered_payload_fails_verification() {
		let pair = P256Pair::generate().unwrap();
		let mut signed = signed_attestation(&pair);
		signed.payload.request_id += 1;
		assert!(matches!(
			verify_execution_attestation(&signed),
			Err(AttestationVerifyError::BadSignature(_))
		));
	}

	#[test]
	fn wrong_engine_id_fails_verification() {
		let pair = P256Pair::generate().unwrap();
		let mut signed = signed_attestation(&pair);
		signed.payload.engine_id = [0u8; 32];
		// Re-sign so only the engine id check can fail.
		let bytes = borsh::to_vec(&signed.payload).unwrap();
		signed.signature = pair.sign(&bytes).unwrap();
		assert!(matches!(
			verify_execution_attestation(&signed),
			Err(AttestationVerifyError::UnexpectedEngine)
		));
	}
}
