//! Mocks for external attest endpoints. Only for testing.

use std::collections::BTreeSet;

use super::{
	types::{NsmDigest, NsmRequest, NsmResponse},
	NsmProvider,
};

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// The `user_data` for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT: &str =
	"a2ec4272c44690b2dc32ed89d4bdd266ec2b0e753dff2f25f08b5d2a15cfe2e6";

/// A valid time to validated the cert chain against in
/// [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_SECONDS_SINCE_EPOCH: u64 = 1_656_030_657;

/// PCR index 0 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR0: &str = "f8bb0133c427bc49aa39f6811a01077ce9ab7e635fa1f5439c9c8bf99754f8230e41b09426b0e595eebdc4d6ed4bc3b6";

/// PCR index 1 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR1: &str = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";

/// PCR index 2 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR2: &str = "c185515d78cb90a2dc1fa49ea232fb44645acd18652c96dd05a92b9c5dbfa36d61d7c7d9e71d51de38de914cd00214bb";

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// The `user_data` for the doc is the hash of the manifest used for the boot
/// e2e test.
pub const MOCK_NSM_ATTESTATION_DOCUMENT: &[u8] =
	include_bytes!("./static/boot_e2e_mock_attestation_doc");

/// Mock Nitro Secure Module endpoint that should only ever be used for testing.
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
			} => NsmResponse::Attestation {
				document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
			},
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
