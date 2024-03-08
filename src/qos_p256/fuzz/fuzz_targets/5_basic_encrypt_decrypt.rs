#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::P256EncryptPair;


// this harness is partially based on the basic_encrypt_decrypt_works() unit test

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control a message plaintext that is encrypted and then decrypted again
    
    // private key generation is non-deterministic: not ideal
    let random_key_pair = P256EncryptPair::generate();
    let random_key_public = random_key_pair.public_key();

    // the encryption is non-deterministic due to the internal random nonce generation
    // not ideal, can't be avoided due to API structure?
    let serialized_envelope = random_key_public.encrypt(data).unwrap();

    // expected to always succeed
    let decrypted_data = random_key_pair.decrypt(&serialized_envelope).unwrap();

    // check roundtrip data consistency, assert should always hold
    assert_eq!(decrypted_data, data);
});
