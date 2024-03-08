#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::AesGcm256Secret;


fuzz_target!(|data: &[u8]| {
    // let the fuzzer create an encrypted envelope to test decrypt() robustness

    // private key generation is non-deterministic: not ideal
    let random_key = AesGcm256Secret::generate();

    // we expect this to fail
    match random_key.decrypt(&data) {
        Ok(_res) => panic!("the fuzzer can't create valid AEAD protected encrypted messages"),
        Err(_err) => {
            return; 
        },
    };
});