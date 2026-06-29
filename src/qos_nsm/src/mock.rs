//! Mocks for external attest endpoints. Only for testing.

use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Mutex,
};

use crate::{
	nitro,
	nsm::NsmProvider,
	types::{NsmDigest, NsmErrorCode, NsmRequest, NsmResponse},
};

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// The `user_data` for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT: &str =
	"a2ec4272c44690b2dc32ed89d4bdd266ec2b0e753dff2f25f08b5d2a15cfe2e6";

/// A valid time to validated the cert chain against in
/// [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_SECONDS_SINCE_EPOCH: u64 = 1_657_117_192;

/// Value of the `timestamp` field in the [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_ATTESTATION_DOC_TIMESTAMP: u64 = 1_657_117_102_484;

/// PCR index 0 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR0: &str = "f8bb0133c427bc49aa39f6811a01077ce9ab7e635fa1f5439c9c8bf99754f8230e41b09426b0e595eebdc4d6ed4bc3b6";

/// PCR index 1 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR1: &str = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";

/// PCR index 2 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR2: &str = "c185515d78cb90a2dc1fa49ea232fb44645acd18652c96dd05a92b9c5dbfa36d61d7c7d9e71d51de38de914cd00214bb";

/// PCR index 3 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR3: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
// This was generate using the `gen_att_doc` script in `integration`.
pub const MOCK_NSM_ATTESTATION_DOCUMENT: &[u8] =
	include_bytes!("./static/mock_attestation_doc");

#[derive(Debug)]
struct MockNsmState {
	max_pcrs: u16,
	pcrs: BTreeMap<u16, Vec<u8>>,
	locked_pcrs: BTreeSet<u16>,
}

impl Default for MockNsmState {
	fn default() -> Self {
		let mut pcrs = BTreeMap::new();
		for index in [
			nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
			nitro::LIVE_MANIFEST_COMMITMENT_PCR_INDEX,
		] {
			pcrs.insert(index, nitro::MANIFEST_COMMITMENT_INITIAL_PCR.to_vec());
		}

		Self {
			max_pcrs: nitro::ATTESTABLE_PCR_COUNT,
			pcrs,
			locked_pcrs: BTreeSet::new(),
		}
	}
}

/// Mock Nitro Secure Module endpoint that should only ever be used for testing.
#[derive(Debug, Default)]
pub struct MockNsm {
	state: Mutex<MockNsmState>,
}

impl MockNsm {
	/// Create a new mock Nitro Secure Module endpoint.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}
}

impl NsmProvider for MockNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation {
				user_data: _,
				nonce: _,
				public_key: _,
			} => NsmResponse::Attestation {
				document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
			},
			NsmRequest::DescribeNSM => {
				let state = self.state.lock().unwrap();
				NsmResponse::DescribeNSM {
					version_major: 1,
					version_minor: 2,
					version_patch: 14,
					module_id: "mock_module_id".to_string(),
					max_pcrs: state.max_pcrs,
					locked_pcrs: state.locked_pcrs.clone(),
					digest: NsmDigest::SHA384,
				}
			}
			NsmRequest::ExtendPCR { index, data } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				if state.locked_pcrs.contains(&index) {
					return NsmResponse::Error(NsmErrorCode::ReadOnlyIndex);
				}

				let current = state
					.pcrs
					.entry(index)
					.or_insert_with(|| vec![0u8; nitro::PCR_SHA384_LEN]);
				let extended =
					nitro::pcr_extend_sha384(current, &data).unwrap().to_vec();
				current.clone_from(&extended);
				NsmResponse::ExtendPCR { data: extended }
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: vec![4, 2, 0, 69] }
			}
			NsmRequest::LockPCR { index } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				state.locked_pcrs.insert(index);
				NsmResponse::LockPCR
			}
			NsmRequest::LockPCRs { range } => {
				let mut state = self.state.lock().unwrap();
				if range > state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				state.locked_pcrs.extend(0..range);
				NsmResponse::LockPCRs
			}
			NsmRequest::DescribePCR { index } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				let lock = state.locked_pcrs.contains(&index);
				let data = state
					.pcrs
					.entry(index)
					.or_insert_with(|| vec![0u8; nitro::PCR_SHA384_LEN])
					.clone();
				NsmResponse::DescribePCR { lock, data }
			}
		}
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		{
			#[cfg(not(feature = "mock_realtime"))]
			{
				Ok(MOCK_ATTESTATION_DOC_TIMESTAMP)
			}
			#[cfg(feature = "mock_realtime")]
			{
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|time| {
						let ms = time.as_millis();
						u64::try_from(ms)
							.map_err(|_| nitro::AttestError::InvalidTimeStamp)
					})
					.map_err(|_| nitro::AttestError::InvalidTimeStamp)?
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mock_nsm_tracks_pcr_state() {
		let nsm = MockNsm::new();

		let NsmResponse::DescribePCR { lock: initial_lock, data: initial_data } =
			nsm.nsm_process_request(NsmRequest::DescribePCR { index: 5 })
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(!initial_lock);
		assert_eq!(initial_data, vec![0u8; nitro::PCR_SHA384_LEN]);

		let NsmResponse::ExtendPCR { data: extended_data } = nsm
			.nsm_process_request(NsmRequest::ExtendPCR {
				index: 5,
				data: b"mock-state-check".to_vec(),
			})
		else {
			panic!("unexpected ExtendPCR response");
		};
		assert_ne!(extended_data, initial_data);

		assert!(matches!(
			nsm.nsm_process_request(NsmRequest::LockPCR { index: 5 }),
			NsmResponse::LockPCR
		));

		let NsmResponse::DescribePCR { lock: locked, data: locked_data } =
			nsm.nsm_process_request(NsmRequest::DescribePCR { index: 5 })
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(locked);
		assert_eq!(locked_data, extended_data);

		assert!(matches!(
			nsm.nsm_process_request(NsmRequest::ExtendPCR {
				index: 5,
				data: b"after-lock".to_vec(),
			}),
			NsmResponse::Error(NsmErrorCode::ReadOnlyIndex)
		));
	}
}
