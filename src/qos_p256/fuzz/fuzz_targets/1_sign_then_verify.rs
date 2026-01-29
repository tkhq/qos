#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_p256::QuorumKey;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; qos_p256::MASTER_SEED_LEN],
	data: Box<[u8]>,
}

// this harness is based on the sign_and_verification_works() unit test

fuzz_target!(|input: FuzzKeyDataStruct| {
	// let the fuzzer control the key and data that is going to be signed

	let keypair = match QuorumKey::from_bytes(&input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

	let input_data: &[u8] = &input.data.clone();

	// produce a signature over the data input the fuzzer controls
	let signature = keypair.sign(input_data).unwrap();

	// verify the just-generated signature
	// this should always succeed
	assert!(keypair.public_key().verify(input_data, &signature).is_ok());
});
