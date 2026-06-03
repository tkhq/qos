//! Execution attestation helpers.

use qos_core::handles::EphemeralKeyHandle;
use qos_crypto::sha_256;

use super::{
	errors::PivotWasmError,
	protocol::{
		PivotWasmExecutionAttestation, PivotWasmExecutionAttestationPayload,
		PIVOT_WASM_ABI_VERSION,
	},
};

pub fn sign_execution_attestation(
	engine_id: [u8; 32],
	policy_hash: [u8; 32],
	function_hash: [u8; 32],
	input: &[u8],
	output: &[u8],
	ephemeral_key_handle: &EphemeralKeyHandle,
) -> Result<PivotWasmExecutionAttestation, PivotWasmError> {
	let payload = PivotWasmExecutionAttestationPayload {
		engine_id,
		policy_hash,
		function_hash,
		input_hash: sha_256(input),
		output_hash: sha_256(output),
		abi_version: PIVOT_WASM_ABI_VERSION,
	};

	let payload_bytes = borsh::to_vec(&payload).map_err(|e| {
		PivotWasmError::runtime(format!("attestation encode: {e}"))
	})?;
	let ephemeral_key =
		ephemeral_key_handle.get_ephemeral_key().map_err(|e| {
			PivotWasmError::runtime(format!("ephemeral key: {e:?}"))
		})?;
	let signature = ephemeral_key
		.sign(&payload_bytes)
		.map_err(|e| PivotWasmError::runtime(format!("signing: {e:?}")))?;

	Ok(PivotWasmExecutionAttestation {
		payload,
		signature,
		public_key: ephemeral_key.public_key().to_bytes(),
	})
}
