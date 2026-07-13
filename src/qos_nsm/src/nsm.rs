//! Endpoints and types for an enclaves attestation flow.

use aws_nitro_enclaves_nsm_api as nsm;

use crate::{nitro, types};

/// Something that implements the Nitro Secure Module endpoints. This is made
/// generic so mock providers can be subbed in for testing. In production use
/// [`Nsm`].
// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
pub trait NsmProvider: Send + Sync {
	/// Create a message with input data and output capacity from a given
	/// request, then send it to the NSM driver via `ioctl()` and wait
	/// for the driver's response.
	/// *Argument 1 (input)*: The NSM request.
	/// *Returns*: The corresponding NSM response from the driver.
	fn nsm_process_request(
		&self,
		request: types::NsmRequest,
	) -> types::NsmResponse;

	/// Requests an attestation document and returns its timestamp in
	/// milliseconds.
	///
	/// # Errors
	///
	/// Returns [`nitro::AttestError`] if the attestation request fails or
	/// the timestamp cannot be extracted.
	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError>;

	/// The DER encoded root certificate authority to trust when verifying
	/// *peer* enclave attestation documents (e.g. during key forwarding).
	///
	/// Defaults to the AWS Nitro root CA: attestation documents produced by
	/// real NSM devices chain up to it. Mock providers override this with
	/// the mock root CA so documents they sign can be verified with the
	/// exact same code path used in production. The trust anchor always
	/// follows the provider; production code cannot end up trusting a mock
	/// root because mock providers are only compiled with the `mock`
	/// feature.
	fn attestation_root_ca_der(&self) -> Vec<u8> {
		nitro::cert_from_pem(nitro::AWS_ROOT_CERT_PEM)
			.expect("hardcoded AWS Nitro root certificate is valid PEM. qed.")
	}
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
