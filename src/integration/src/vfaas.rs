//! Host-side helpers for talking to `pivot_vfaas`.
//!
//! Owns the signing payload format (`DOMAIN || sha256(wasm)`) so the pivot
//! and tooling can never drift on that contract. Also exposes verification
//! of [`SignedExecutionAttestation`] for clients.

use qos_crypto::sha_256;
use qos_p256::{P256Error, P256Pair, P256Public};

use crate::{
	Decision, ExecutionAttestation, SignedExecutionAttestation,
	VFAAS_POLICY_DOMAIN, VFAAS_PROGRAM_DOMAIN, VfaasMsg,
};

/// Errors that can occur when interacting with `pivot_vfaas`.
#[derive(Debug)]
pub enum VfaasError {
	/// Signing failed.
	SigningFailed(P256Error),
	/// Attestation signature verification failed.
	VerifyFailed(P256Error),
	/// Ephemeral public key in the attestation could not be parsed.
	BadEphemeralKey(P256Error),
	/// Attestation payload Borsh serialization failed.
	SerializationFailed(std::io::Error),
	/// The decision in the attestation does not match the carried decision.
	DecisionMismatch,
}

/// Generate a fresh owner P256 pair.
///
/// # Errors
///
/// Returns [`P256Error`] if key generation fails.
pub fn owner_keygen() -> Result<P256Pair, P256Error> {
	P256Pair::generate()
}

/// Produce the signed payload for a program hash.
///
/// Builds `VFAAS_PROGRAM_DOMAIN || sha256(wasm)` and signs it with the owner
/// pair. The pivot reconstructs the same payload to verify.
///
/// # Errors
///
/// Returns [`P256Error`] if signing fails.
pub fn sign_program_hash(
	owner: &P256Pair,
	wasm: &[u8],
) -> Result<Vec<u8>, P256Error> {
	let payload = domain_payload(VFAAS_PROGRAM_DOMAIN, wasm);
	owner.sign(&payload)
}

/// Produce the signed payload for a policy hash.
///
/// # Errors
///
/// Returns [`P256Error`] if signing fails.
pub fn sign_policy_hash(
	owner: &P256Pair,
	wasm: &[u8],
) -> Result<Vec<u8>, P256Error> {
	let payload = domain_payload(VFAAS_POLICY_DOMAIN, wasm);
	owner.sign(&payload)
}

/// Build a [`VfaasMsg::RegisterProgramRequest`] for the given WASM bytes,
/// signed by `owner`.
///
/// # Errors
///
/// Returns [`P256Error`] if signing fails.
pub fn build_register_program(
	owner: &P256Pair,
	wasm: Vec<u8>,
) -> Result<VfaasMsg, P256Error> {
	let signature = sign_program_hash(owner, &wasm)?;
	Ok(VfaasMsg::RegisterProgramRequest { wasm, signature })
}

/// Build a [`VfaasMsg::RegisterPolicyRequest`] for the given WASM bytes,
/// signed by `owner`.
///
/// # Errors
///
/// Returns [`P256Error`] if signing fails.
pub fn build_register_policy(
	owner: &P256Pair,
	wasm: Vec<u8>,
) -> Result<VfaasMsg, P256Error> {
	let signature = sign_policy_hash(owner, &wasm)?;
	Ok(VfaasMsg::RegisterPolicyRequest { wasm, signature })
}

/// Verify a [`SignedExecutionAttestation`] against the embedded ephemeral
/// public key.
///
/// This is the canonical client-side verification: anyone holding the
/// attestation can confirm the bytes were signed by an enclave that held the
/// referenced ephemeral key. Tying the ephemeral key to a hardware attestation
/// doc (NSM) is the next layer up and is left to the caller.
///
/// # Errors
///
/// Returns [`VfaasError`] if the embedded key is malformed, the payload
/// fails to serialize, or the signature does not verify.
pub fn verify_execution_attestation(
	signed: &SignedExecutionAttestation,
) -> Result<(), VfaasError> {
	let pubkey = P256Public::from_bytes(&signed.ephemeral_public_key)
		.map_err(VfaasError::BadEphemeralKey)?;
	let payload = borsh::to_vec(&signed.attestation)
		.map_err(VfaasError::SerializationFailed)?;
	pubkey
		.verify(&payload, &signed.signature)
		.map_err(VfaasError::VerifyFailed)
}

/// Convenience: check whether a verified attestation describes an allowed
/// execution. Does NOT itself verify the signature — call
/// [`verify_execution_attestation`] first.
#[must_use]
pub fn attestation_allowed(attestation: &ExecutionAttestation) -> bool {
	matches!(attestation.decision, Decision::Allow)
}

fn domain_payload(domain: &[u8], wasm: &[u8]) -> Vec<u8> {
	let hash = sha_256(wasm);
	let mut payload = Vec::with_capacity(domain.len() + hash.len());
	payload.extend_from_slice(domain);
	payload.extend_from_slice(&hash);
	payload
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sign_and_verify_program_round_trip() {
		let owner = owner_keygen().unwrap();
		let wasm = b"fake-wasm-bytes".to_vec();
		let sig = sign_program_hash(&owner, &wasm).unwrap();
		let payload = domain_payload(VFAAS_PROGRAM_DOMAIN, &wasm);
		owner.public_key().verify(&payload, &sig).unwrap();
	}

	#[test]
	fn program_signature_does_not_verify_as_policy() {
		let owner = owner_keygen().unwrap();
		let wasm = b"fake-wasm-bytes".to_vec();
		let sig = sign_program_hash(&owner, &wasm).unwrap();
		let policy_payload = domain_payload(VFAAS_POLICY_DOMAIN, &wasm);
		assert!(
			owner.public_key().verify(&policy_payload, &sig).is_err(),
			"domain separation should reject program sig under policy domain"
		);
	}

	#[test]
	fn build_register_program_round_trips() {
		let owner = owner_keygen().unwrap();
		let wasm = b"some-wasm".to_vec();
		let msg = build_register_program(&owner, wasm.clone()).unwrap();
		match msg {
			VfaasMsg::RegisterProgramRequest {
				wasm: w,
				signature,
			} => {
				assert_eq!(w, wasm);
				let payload = domain_payload(VFAAS_PROGRAM_DOMAIN, &wasm);
				owner.public_key().verify(&payload, &signature).unwrap();
			}
			_ => panic!("expected RegisterProgramRequest"),
		}
	}
}
