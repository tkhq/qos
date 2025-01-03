#![no_main]

use libfuzzer_sys::fuzz_target;

// use qos_p256::encrypt::P256EncryptPair;
use qos_p256::encrypt::P256EncryptPublic;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	public: Box<[u8]>, // this should be 65 byte in theory, but both 33 and 65 byte work
	secret: Box<[u8]>,
	data: Box<[u8]>,
}

fuzz_target!(|input: FuzzKeyDataStruct| {
	let pubkey = match P256EncryptPublic::from_bytes(&input.public) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};
	
	match pubkey.decrypt_from_shared_secret(&input.secret, &input.data) {
		Ok(_res) => panic!(
			"the fuzzer should be unable to create a validly signed encrypted message"
		),
		Err(_err) => {
			return;
		}
	};
});
