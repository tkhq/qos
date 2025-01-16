#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::P256EncryptPair;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; qos_p256::MASTER_SEED_LEN],
	data: Box<[u8]>,
}

fuzz_target!(|input: FuzzKeyDataStruct| {
	let key = match P256EncryptPair::from_bytes(&input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

	// let the fuzzer control an encrypted message ciphertext to test decrypt() robustness
	match key.decrypt(&input.data) {
		Ok(_res) => panic!(
			"the fuzzer should be unable to create a validly signed encrypted message"
		),
		Err(_err) => {
			return;
		}
	};
});
