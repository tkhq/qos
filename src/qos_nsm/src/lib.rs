//! Endpoints and types for an enclaves attestation flow.

pub mod nitro;
mod nsm;
pub mod types;

pub use nsm::{Nsm, NsmProvider};

#[cfg(any(feature = "mock", test))]
pub mod mock;

#[cfg(any(feature = "mock", test))]
pub mod mocknsm;

#[cfg(test)]
mod tests {
	use crate::{
		NsmProvider,
		nitro::unsafe_attestation_doc_from_der,
		types::{NsmDigest, NsmRequest, NsmResponse},
	};

	#[test]
	fn static_mock_attestation_doc_is_unchanged() {
		let response =
			crate::mock::MockNsm.nsm_process_request(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: None,
			});

		let NsmResponse::Attestation { document } = response else {
			panic!("expected attestation response");
		};

		assert_eq!(document, crate::mock::MOCK_NSM_ATTESTATION_DOCUMENT);
	}

	#[test]
	fn mocknsm_attestation_doc_echoes_request_fields() {
		let user_data = vec![1, 2, 3];
		let nonce = vec![4, 5, 6];
		let public_key = vec![7, 8, 9];

		let response = crate::mocknsm::MockNsm.nsm_process_request(
			NsmRequest::Attestation {
				user_data: Some(user_data.clone()),
				nonce: Some(nonce.clone()),
				public_key: Some(public_key.clone()),
			},
		);

		let NsmResponse::Attestation { document } = response else {
			panic!("expected attestation response");
		};

		let doc = unsafe_attestation_doc_from_der(&document).unwrap();
		assert_eq!(doc.user_data.unwrap().as_ref(), user_data.as_slice());
		assert_eq!(doc.nonce.unwrap().as_ref(), nonce.as_slice());
		assert_eq!(doc.public_key.unwrap().as_ref(), public_key.as_slice());
	}

	#[test]
	fn mocknsm_attestation_doc_has_valid_mock_measurements_and_certs() {
		let document =
			crate::mocknsm::attestation_doc_der(None, None, None).unwrap();
		let doc = unsafe_attestation_doc_from_der(&document).unwrap();

		assert_eq!(doc.digest, aws_nitro_enclaves_nsm_api::api::Digest::SHA384);
		assert!(!doc.module_id.is_empty());
		assert_ne!(doc.timestamp, 0);
		assert!(!doc.certificate.is_empty());
		assert!(!doc.cabundle.is_empty());
		assert!(doc.cabundle.iter().all(|cert| !cert.is_empty()));

		for index in 0..=3 {
			assert_eq!(doc.pcrs.get(&index).unwrap().as_ref(), &[0u8; 48]);
		}
	}

	#[test]
	fn mocknsm_uses_existing_mock_responses_for_non_attestation_requests() {
		let response = crate::mocknsm::MockNsm
			.nsm_process_request(NsmRequest::DescribeNSM);

		assert_eq!(
			response,
			NsmResponse::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: "mock_module_id".to_owned(),
				max_pcrs: 1024,
				locked_pcrs: [90, 91, 92].into(),
				digest: NsmDigest::SHA256,
			}
		);
	}
}
