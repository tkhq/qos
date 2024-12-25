#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_nsm::nitro::{attestation_doc_from_der, cert_from_pem};

// working root cert, use as example
use qos_nsm::nitro::AWS_ROOT_CERT_PEM;

// mirrors qos_nsm::mock::MOCK_SECONDS_SINCE_EPOCH, which isn't available on all builds
// this is just an example timestamp
pub const MOCK_SECONDS_SINCE_EPOCH: u64 = 1_657_117_192;


fuzz_target!(|data: &[u8]| {
	let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
    // test attestation conversion function
	let attestation_result = attestation_doc_from_der(
		data,
		&root_cert[..],
		MOCK_SECONDS_SINCE_EPOCH,
	);

	match attestation_result {
		Err(_) => {}
		Ok(_reconstructed) => {
			// TODO human debug, signals how often this is hit
			println!("succeeded parsing");
		}
	}
});
