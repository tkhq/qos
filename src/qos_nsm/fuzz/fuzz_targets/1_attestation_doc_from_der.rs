#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_nsm::nitro::{attestation_doc_from_der, cert_from_pem};
// working root cert, use as example
use qos_nsm::nitro::AWS_ROOT_CERT_PEM;
// this is just an example timestamp
use qos_nsm::mock::MOCK_SECONDS_SINCE_EPOCH;

fuzz_target!(|data: &[u8]| {
	let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
	// test attestation conversion function
	// this includes verification of signatures, and is unlikely to succeed
	// unless on variants of a validly signed doc
	let attestation_result = attestation_doc_from_der(
		data,
		&root_cert[..],
		MOCK_SECONDS_SINCE_EPOCH,
	);

	match attestation_result {
		Err(_) => {}
		Ok(_reconstructed) => {
			// debug print, signals how often this path is hit, remove later
			println!("succeeded parsing, data length: {}", data.len());
		}
	}
});
