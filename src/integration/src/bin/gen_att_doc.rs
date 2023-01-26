//! Helper script to generate a mock attestation document that works for the
//! boot_e2e.
//!
//! Rough use instructions:
//!
//! 1) On the aws host run `make image`, `build-enclave` and then run the
//! enclave, ensuring that debug mode is not enabled. Debug mode will lead to
//! the PCRs being zeroed out.
//!
//! 2) Take the PCRs output from `build-enclave` and update the hardcoded values
//! in the boot e2e test.
//!
//! 3) Run the test and log the value of the manifest hash.
//!
//! 4) Update `MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT` with the manifest hash.
//!
//! 5) Run this script (the enclave should be running from step 1).
//!
//! 6) Commit the updated files.

#[tokio::main]
async fn main() {
	#[cfg(feature = "mock")]
	{
		use std::{fs, path::Path};

		use qos_client::request;
		use qos_core::{hex, protocol::msg::ProtocolMsg};
		use qos_crypto::RsaPair;
		use qos_nsm::{
			mock::MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT,
			types::{NsmRequest, NsmResponse},
		};

		const EPHEMERAL_KEY_RELATIVE_PATH: &str =
			"./qos_core/src/protocol/attestor/static/boot_e2e_mock_eph.secret";

		let uri = "http://127.0.0.1:3000/message";

		let eph_path = Path::new(EPHEMERAL_KEY_RELATIVE_PATH);
		// Create / read in mock ephemeral key
		let eph_pair = if eph_path.exists() {
			RsaPair::from_pem_file(&eph_path).unwrap()
		} else {
			let pair = RsaPair::generate().unwrap();
			fs::write(&eph_path, pair.private_key_to_pem().unwrap()).unwrap();

			pair
		};

		// Create an nsm attestation request
		let manifest_hash =
			hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap();
		let nsm_request = NsmRequest::Attestation {
			user_data: Some(manifest_hash),
			nonce: None,
			public_key: Some(eph_pair.public_key_to_pem().unwrap()),
		};
		let req = ProtocolMsg::NsmRequest { nsm_request };

		println!("Making request to {uri} ...");
		let cose_sign1 = match request::post(uri, &req).unwrap() {
			ProtocolMsg::NsmResponse {
				nsm_response: NsmResponse::Attestation { document },
			} => document,
			r => panic!("Unexpected response: {:?}", r),
		};

		let att_path =
			"./qos_core/src/protocol/attestor/static/boot_e2e_mock_attestation_doc";
		fs::write(&att_path, cose_sign1).unwrap();

		println!("Done");
	}
	#[cfg(not(feature = "mock"))]
	{
		panic!("qos_test's \"mock\" feature must be enabled to run this binary")
	}
}
