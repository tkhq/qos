//! Endpoints and types for an enclaves attestation flow.

use aws_nitro_enclaves_nsm_api as nsm;

use crate::{nitro, types};

/// Something that implements the Nitro Secure Module endpoints. This is made
/// generic so mock providers can be subbed in for testing. In production use
/// [`Nsm`].
// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
pub trait NsmProvider {
	/// Create a message with input data and output capacity from a given
	/// request, then send it to the NSM driver via `ioctl()` and wait
	/// for the driver's response.
	/// *Argument 1 (input)*: The NSM request.
	/// *Returns*: The corresponding NSM response from the driver.
	fn nsm_process_request(
		&self,
		request: types::NsmRequest,
	) -> types::NsmResponse;

	/// requests an attestation document and returns its timestamp in
	/// milliseconds
	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError>;
}

/// Nitro Secure Module endpoints.
pub struct Nsm;
impl NsmProvider for Nsm {
	fn nsm_process_request(
		&self,
		request: types::NsmRequest,
	) -> types::NsmResponse {
		let fd = nsm::driver::nsm_init();
		let response =
			nsm::driver::nsm_process_request(fd, request.into()).into();
		nsm::driver::nsm_exit(fd);
		response
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		let nsm_request = types::NsmRequest::Attestation {
			user_data: None,
			nonce: None,
			public_key: None,
		};

		let nsm_response = self.nsm_process_request(nsm_request);
		match nsm_response {
			types::NsmResponse::Attestation { document } => {
				let attestation_document =
					nitro::unsafe_attestation_doc_from_der(&document)?;
				Ok(attestation_document.timestamp)
			}
			resp => Err(nitro::AttestError::UnexpectedNsmResponse(resp)),
		}
	}
}
