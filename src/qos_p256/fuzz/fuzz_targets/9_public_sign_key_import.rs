#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPair;
use qos_p256::sign::P256SignPublic;

// this harness is partially based on the public_key_round_trip_bytes_works() unit test

// this is a simpler variant of another public key import harness

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control the P256 signing pubkey
    
    
    // import public key from bytes
    // silently exit in case of errors
    let pubkey_special = match P256SignPublic::from_bytes(data) {
        Ok(pubkey) => pubkey,
        Err(_err) => {
            return; 
        },
    };

    // static plaintext message
    let message = b"a message to authenticate";
    
    // Improvement: replace this with a static pre-recorded signature, we just need a (wrong) signature
    let pair = P256SignPair::generate();
    // sign with secret key
    let signature = pair.sign(message).unwrap();

    // we expect this to not succeed since the pubkeys do not match up
    assert!(!pubkey_special.verify(message, &signature).is_ok());
});
