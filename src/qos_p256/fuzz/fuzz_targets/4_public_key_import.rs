#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPair;
// use qos_p256::sign::P256SignPublic;

use qos_p256::P256Pair;
use qos_p256::P256Public;

#[cfg(feature = "fuzzer_corpus_seed1")]
use libfuzzer_sys::fuzz_mutator;

// this helps the fuzzer over the major obstacle of learning what a valid P256Public object looks like
#[cfg(feature = "fuzzer_corpus_seed1")]
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, _seed: u32| {

    // this is random and does not depend on the input
    let random_key_pair = P256Pair::generate().unwrap();

    let mut public_bytes = random_key_pair.public_key().to_bytes();
    let public_bytes_length = public_bytes.len();

    // this mutates the generated data in-place in its buffer
    // and denies buffer length extensions, which is overly restrictive
    let mutated_data_size = libfuzzer_sys::fuzzer_mutate(
        &mut public_bytes,
        public_bytes_length,
        public_bytes_length,
    );

    // calculate the new requested output size and return the corresponding data
    let new_size = std::cmp::min(max_size, public_bytes_length);
    data[..new_size].copy_from_slice(&public_bytes[..new_size]);
    new_size
});

// this harness is partially based on the public_key_round_trip_bytes_works() unit test

fuzz_target!(|data: &[u8]| {
    // let the fuzzer control the P256 signing pubkey and P256 encryption pubkey
    
    // the fuzzer has problems synthesizing a working input without additional help
    // see fuzz_mutator!() for a workaround

    // import public keys from bytes
    // silently exit in case of errors
    let pubkey_special = match P256Public::from_bytes(data) {
        Ok(pubkey) => pubkey,
        Err(_err) => {
            return; 
        },
    };

    // static plaintext message
    let message = b"a message to authenticate";
    
    // Improvement: replace this with a static pre-recorded signature, we just need a (wrong) signature
    let random_key_pair = P256SignPair::generate();
    // sign with secret key
    let signature = random_key_pair.sign(message).unwrap();

    // we expect this to not succeed since the pubkeys do not match up
    assert!(!pubkey_special.verify(message, &signature).is_ok());
});
