use aws_nitro_enclaves_nsm_api as nsm;

use crate::protocol::{NsmRequest, NsmResponse};

mod mock;
pub use mock::{MockNsm, MOCK_NSM_ATTESTATION_DOCUMENT};

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
pub trait NsmProvider {
	fn nsm_process_request(&self, fd: i32, request: NsmRequest) -> NsmResponse;

	fn nsm_init(&self) -> i32;

	fn nsm_exit(&self, fd: i32);
}

pub struct Nsm;
impl NsmProvider for Nsm {
	fn nsm_process_request(&self, fd: i32, request: NsmRequest) -> NsmResponse {
		nsm::driver::nsm_process_request(fd, request)
	}

	fn nsm_init(&self) -> i32 {
		nsm::driver::nsm_init()
	}

	fn nsm_exit(&self, fd: i32) {
		nsm::driver::nsm_exit(fd)
	}
}
