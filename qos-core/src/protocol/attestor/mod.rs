use aws_nitro_enclaves_nsm_api as nsm;

mod mock;
pub mod types;
pub use mock::{MockNsm, MOCK_NSM_ATTESTATION_DOCUMENT};

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
}
