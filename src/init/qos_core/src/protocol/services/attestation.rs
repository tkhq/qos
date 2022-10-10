use crate::protocol::{
	attestor::{
		types::{NsmRequest, NsmResponse},
		NsmProvider,
	},
	ProtocolError, ProtocolState, QosHash,
};

pub(in crate::protocol) fn live_attestation_doc(
	state: &mut ProtocolState,
) -> Result<NsmResponse, ProtocolError> {
	let ephemeral_public_key =
		state.handles.get_ephemeral_key()?.public_key_to_pem()?;
	let manifest_hash =
		state.handles.get_manifest_envelope()?.manifest.qos_hash().to_vec();

	Ok(get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_public_key,
		manifest_hash,
	))
}

pub(super) fn get_post_boot_attestation_doc(
	attestor: &dyn NsmProvider,
	ephemeral_public_key: Vec<u8>,
	manifest_hash: Vec<u8>,
) -> NsmResponse {
	let request = NsmRequest::Attestation {
		user_data: Some(manifest_hash),
		nonce: None,
		public_key: Some(ephemeral_public_key),
	};

	let fd = attestor.nsm_init();
	attestor.nsm_process_request(fd, request)
}
