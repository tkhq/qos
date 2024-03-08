#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPair;
use qos_p256::sign::P256SignPublic;

// this harness is based on the public_key_round_trip_bytes_works() unit test

fuzz_target!(|data: &[u8]| {

    // let the fuzzer control the P256 secret key

    // create private key from bytes, derive public key
    // silently abort on failures
    // we expect only 32 byte vector inputs to succeed here
    let pair = match P256SignPair::from_bytes(data) {
        Ok(pair) => pair,
        Err(_err) => {
            return; 
        },
    };
    
    // derive public key and export it
    let bytes_public = pair.public_key().to_bytes();
    
    // static plaintext message
    let message = b"a message to authenticate";

    // sign with private key
    let signature = pair.sign(message).unwrap();

    // re-import public key from bytes
    // this should always succeed since we just generated it
    let public = P256SignPublic::from_bytes(&bytes_public).unwrap();

    // expect the signature verification with the reconstructed pubkey to always succeed
    assert!(pubkey_special.verify(message, &signature).is_ok());
});
