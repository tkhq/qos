#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::AesGcm256Secret;


// this harness is partially based on the encrypt_decrypt_round_trip() unit test

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control a message plaintext that is encrypted and then decrypted again
    
    // private key generation is non-deterministic: not ideal
    let random_key = AesGcm256Secret::generate();

    // the encryption is non-deterministic due to the internal random nonce generation
    // not ideal, can't be avoided due to API structure?
    // expected to always succeed
    let encrypted_envelope = random_key.encrypt(data).unwrap();

    // expected to always succeed
    let decrypted_data = random_key.decrypt(&encrypted_envelope).unwrap();

    // check roundtrip data consistency, assert should always hold
    assert_eq!(decrypted_data, data);
});