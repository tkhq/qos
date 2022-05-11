use aws_nitro_enclaves_nsm_api as nsm;
use std::collections::BTreeSet;

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
pub trait NsmProvider {
	fn nsm_process_request(
		&self,
		fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response;

	fn nsm_init(&self) -> i32;

	fn nsm_exit(&self, fd: i32);
}

pub struct Nsm {}
impl NsmProvider for Nsm {
	fn nsm_process_request(
		&self,
		fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response {
		nsm::driver::nsm_process_request(fd, request)
	}

	fn nsm_init(&self) -> i32 {
		nsm::driver::nsm_init()
	}

	fn nsm_exit(&self, fd: i32) {
		nsm::driver::nsm_exit(fd)
	}
}

/// TODO - this should be moved to its own crate as it will likely need some
/// additional deps like Serde
pub struct MockNsm {}

impl NsmProvider for MockNsm {
	fn nsm_process_request(
		&self,
		_fd: i32,
		request: nsm::api::Request,
	) -> nsm::api::Response {
		use nsm::api::{Request as Req, Response as Resp};
		println!("MockNsm::process_request request={:?}", request);
		match request {
			Req::Attestation { user_data: _, nonce: _, public_key: _ } => {
				// TODO: this should be a CBOR-encoded AttestationDocument as
				// the payload
				Resp::Attestation { document: Vec::new() }
			}
			Req::DescribeNSM => Resp::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: "mock_module_id".to_string(),
				max_pcrs: 1024,
				locked_pcrs: BTreeSet::from([90, 91, 92]),
				digest: nsm::api::Digest::SHA256,
			},
			Req::ExtendPCR { index: _, data: _ } => {
				Resp::ExtendPCR { data: vec![3, 4, 7, 4] }
			}
			Req::GetRandom => Resp::GetRandom { random: vec![4, 2, 0, 69] },
			Req::LockPCR { index: _ } => Resp::LockPCR,
			Req::LockPCRs { range: _ } => Resp::LockPCRs,
			Req::DescribePCR { index: _ } => {
				Resp::DescribePCR { lock: false, data: vec![3, 4, 7, 4] }
			}
			_ => Resp::Error(nsm::api::ErrorCode::InternalError),
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
