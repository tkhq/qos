#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::AesGcm256Secret;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; qos_p256::MASTER_SEED_LEN],
	data: Box<[u8]>,
}

// this harness is partially based on the encrypt_decrypt_round_trip() unit test

fuzz_target!(|input: FuzzKeyDataStruct| {
	// let the fuzzer control a message plaintext that is encrypted and then decrypted again

	// private key generation is non-deterministic: not ideal
	// let random_key = AesGcm256Secret::generate();
	let random_key = match AesGcm256Secret::from_bytes(input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

	let data = input.data.to_vec();

	// the encryption is non-deterministic due to the internal random nonce generation
	// not ideal, can't be avoided due to API structure?
	// expected to always succeed
	let encrypted_envelope = random_key.encrypt(&data[..]).unwrap();

	// expected to always succeed
	let decrypted_data = random_key.decrypt(&encrypted_envelope).unwrap();
	// check roundtrip data consistency, assert should always hold
	assert_eq!(decrypted_data, data);

	let mut corrupted_encrypted_envelope = encrypted_envelope.clone();
	let last_element_index_envelope = corrupted_encrypted_envelope.len() - 1;
	// flip one bit in the end of the message as a simple example of data corruption
	corrupted_encrypted_envelope[last_element_index_envelope] =
		corrupted_encrypted_envelope[last_element_index_envelope] ^ 1;
	// expect detection of the corruption
	assert!(random_key.decrypt(&corrupted_encrypted_envelope).is_err());
});
