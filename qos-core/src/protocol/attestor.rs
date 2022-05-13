use std::collections::BTreeSet;

use aws_nitro_enclaves_nsm_api as nsm;

use crate::protocol::{NsmDigest, NsmRequest, NsmResponse};

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
pub trait NsmProvider {
	fn nsm_process_request(&self, fd: i32, request: NsmRequest) -> NsmResponse;

	fn nsm_init(&self) -> i32;

	fn nsm_exit(&self, fd: i32);
}

pub struct Nsm;
impl NsmProvider for Nsm {
	fn nsm_process_request(&self, fd: i32, request: NsmRequest) -> NsmResponse {
		nsm::driver::nsm_process_request(fd, request.into()).into()
	}

	fn nsm_init(&self) -> i32 {
		nsm::driver::nsm_init()
	}

	fn nsm_exit(&self, fd: i32) {
		nsm::driver::nsm_exit(fd)
	}
}

/// TODO: - this should be moved to its own crate as it will likely need some
/// additional deps like Serde
pub struct MockNsm;

impl NsmProvider for MockNsm {
	fn nsm_process_request(
		&self,
		_fd: i32,
		request: NsmRequest,
	) -> NsmResponse {
		match request {
			NsmRequest::Attestation {
				user_data: _,
				nonce: _,
				public_key: _,
			} => {
				// TODO: this should be a CBOR-encoded AttestationDocument as
				// the payload
				NsmResponse::Attestation { document: Vec::new() }
			}
			NsmRequest::DescribeNSM => NsmResponse::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: "mock_module_id".to_string(),
				max_pcrs: 1024,
				locked_pcrs: BTreeSet::from([90, 91, 92]),
				digest: NsmDigest::SHA256,
			},
			NsmRequest::ExtendPCR { index: _, data: _ } => {
				NsmResponse::ExtendPCR { data: vec![3, 4, 7, 4] }
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: vec![4, 2, 0, 69] }
			}
			NsmRequest::LockPCR { index: _ } => NsmResponse::LockPCR,
			NsmRequest::LockPCRs { range: _ } => NsmResponse::LockPCRs,
			NsmRequest::DescribePCR { index: _ } => {
				NsmResponse::DescribePCR { lock: false, data: vec![3, 4, 7, 4] }
			}
		}
	}

	fn nsm_init(&self) -> i32 {
		33
	}

	fn nsm_exit(&self, fd: i32) {
		// Should be hardcoded to value returned by nsm_init
		assert_eq!(fd, 33);
		println!("nsm_exit");
	}
}
