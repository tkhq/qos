#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_nsm::nitro::unsafe_attestation_doc_from_der;
use qos_nsm::nitro::verify_attestation_doc_against_user_input;

// constants are copied from the mock system, and represent dummy values

use qos_nsm::mock::{
	MOCK_PCR0, MOCK_PCR1, MOCK_PCR2, MOCK_PCR3,
	MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT,
};

fuzz_target!(|data: &[u8]| {
	// use the unsafe conversion variant without verification of cryptographic properties
	// this allows the fuzzer to more often generate a working attestation document
	let attestation_result = unsafe_attestation_doc_from_der(data);

	match attestation_result {
		Err(_) => {}
		Ok(reconstructed) => {
			// test the intended target function
			let _ = verify_attestation_doc_against_user_input(
				&reconstructed,
				&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT)
					.unwrap(),
				&qos_hex::decode(MOCK_PCR0).unwrap(),
				&qos_hex::decode(MOCK_PCR1).unwrap(),
				&qos_hex::decode(MOCK_PCR2).unwrap(),
				&qos_hex::decode(MOCK_PCR3).unwrap(),
			);
		}
	}
});
