#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPair;
use qos_p256::sign::P256SignPublic;

// this harness is based on the public_key_round_trip_bytes_works() unit test

fuzz_target!(|data: &[u8]| {

    // This setup is not ideal, as the fuzzer-controlled data input only has a 
    // minor influence on the tested public key round trip check
    
    // Generate a non-deterministically random P256 key
    //
    // This deviates from fully deterministic fuzz behavior,
    // but gives us a chance to randomly discover key-specific issues
    let pair = P256SignPair::generate();

    // derive public key and export it to bytes
    let bytes_public = pair.public_key().to_bytes();

    // create valid signature
    let signature = pair.sign(data).unwrap();

    // re-import public key from bytes
    // this should always succeed since we just generated and exported it
    let public = P256SignPublic::from_bytes(&bytes_public).unwrap();

    // expect the signature verification with the reconstructed pubkey to always succeed
    assert!(public.verify(data, &signature).is_ok());
});
