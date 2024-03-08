#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::encrypt::P256EncryptPair;

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control an encrypted message ciphertext to test decrypt() robustness
    
    // private key generation is non-deterministic: not ideal
    let random_key_pair = P256EncryptPair::generate();

    match random_key_pair.decrypt(&data) {
        Ok(_res) => panic!("the fuzzer should be unable to create a validly signed message"),
        Err(_err) => {
            return; 
        },
    };
});
