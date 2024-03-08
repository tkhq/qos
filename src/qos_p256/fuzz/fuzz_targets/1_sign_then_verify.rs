#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::P256Pair;

// this harness is based on the sign_and_verification_works() unit test

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control data that is going to be signed

    // Generate a non-deterministically random P256 key
    //
    // This deviates from fully deterministic fuzz behavior,
    // but gives us a chance to randomly discover key-specific issues
    let random_key_pair = P256Pair::generate().unwrap();

    // produce a signature over the data input the fuzzer controls
    let signature = random_key_pair.sign(data).unwrap();

    // verify the just-generated signature
    // this should always succeed
    assert!(random_key_pair.public_key().verify(data, &signature).is_ok());
});
