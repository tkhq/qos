#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::AesGcm256Secret;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; 32], // AES256_KEY_LEN == 32
	data: Box<[u8]>,
}

// this harness is partially based on the encrypt_decrypt_round_trip() unit test

fuzz_target!(|input: FuzzKeyDataStruct| {
	// let the fuzzer control a message plaintext that is encrypted and then decrypted again

	// private key generation is non-deterministic: not ideal
	// let random_key = AesGcm256Secret::generate();
	let key = match AesGcm256Secret::from_bytes(input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

    // we expect this to fail
    match key.decrypt(&input.data) {
        Ok(_res) => panic!("the fuzzer can't create valid AEAD protected encrypted messages"),
        Err(_err) => {
            return; 
        },
    };
});