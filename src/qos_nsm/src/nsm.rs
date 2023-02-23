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
	/// *Argument 1 (input)*: The descriptor to the NSM device file.
	/// *Argument 2 (input)*: The NSM request.
	/// *Returns*: The corresponding NSM response from the driver.
	fn nsm_process_request(
		&self,
		fd: i32,
		request: types::NsmRequest,
	) -> types::NsmResponse;

	/// NSM library initialization function.
	/// *Returns*: A descriptor for the opened device file.
	fn nsm_init(&self) -> i32;

	/// NSM library exit function.
	/// *Argument 1 (input)*: The descriptor for the opened device file, as
	/// obtained from `nsm_init()`.
	fn nsm_exit(&self, fd: i32);

	// requests an attestation document and returns its timestamp in
	// milliseconds
	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError>;
}

/// Nitro Secure Module endpoints.
pub struct Nsm;
impl NsmProvider for Nsm {
	fn nsm_process_request(
		&self,
		fd: i32,
		request: types::NsmRequest,
	) -> types::NsmResponse {
		nsm::driver::nsm_process_request(fd, request.into()).into()
	}

	fn nsm_init(&self) -> i32 {
		nsm::driver::nsm_init()
	}

	fn nsm_exit(&self, fd: i32) {
		nsm::driver::nsm_exit(fd);
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		let nsm_request = types::NsmRequest::Attestation {
			user_data: None,
			nonce: None,
			public_key: None,
		};

		let fd = self.nsm_init();
		let nsm_response = self.nsm_process_request(fd, nsm_request);

		let result = match nsm_response {
			types::NsmResponse::Attestation { document } => {
				let attestation_document =
					nitro::unsafe_attestation_doc_from_der(&document)?;
				Ok(attestation_document.timestamp)
			}
			resp => Err(nitro::AttestError::UnexpectedNsmResponse(resp)),
		};

		self.nsm_exit(fd);
		result
	}
}
