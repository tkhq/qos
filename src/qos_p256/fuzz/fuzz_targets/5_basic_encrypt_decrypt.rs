#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::P256EncryptPair;

// this harness is partially based on the basic_encrypt_decrypt_works() unit test

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; qos_p256::MASTER_SEED_LEN],
	data: Box<[u8]>,
}

fuzz_target!(|input: FuzzKeyDataStruct| {
	// let the fuzzer control a message plaintext that is encrypted and then decrypted again

	// private key generation is non-deterministic: not ideal
	let key_pair = match P256EncryptPair::from_bytes(&input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

	let public_key = key_pair.public_key();
	let data = input.data.to_vec();

	// the encryption is non-deterministic due to the internal random nonce generation
	// not ideal, can't be avoided due to API structure?
	let serialized_envelope = public_key.encrypt(&data[..]).unwrap();

	// expected to always succeed
	let decrypted_data = key_pair.decrypt(&serialized_envelope).unwrap();

	// check roundtrip data consistency, assert should always hold
	assert_eq!(decrypted_data, data);
});
