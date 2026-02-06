#![no_main]

#[cfg(feature = "fuzzer_corpus_seed1")]
use libfuzzer_sys::fuzz_mutator;
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzer_corpus_seed1")]
use qos_p256::QuorumKey;
use qos_p256::QuorumKeyPublic;

// this helps the fuzzer over the major obstacle of learning what a valid QuorumKeyPublic object looks like
#[cfg(feature = "fuzzer_corpus_seed1")]
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
	// this is random and does not depend on the input
	let random_key_pair = QuorumKey::generate().unwrap();

	let mut public_bytes = random_key_pair.public_key().to_bytes();
	let public_bytes_length = public_bytes.len();

	// this mutates the generated data in-place in its buffer
	// and denies buffer length extensions, which is overly restrictive
	let _mutated_data_size = libfuzzer_sys::fuzzer_mutate(
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
	let pubkey_special = match QuorumKeyPublic::from_bytes(data) {
		Ok(pubkey) => pubkey,
		Err(_err) => {
			return;
		}
	};

	// we don't have the private key that belongs to this public key,
	// so we can't generate valid signatures
	// however, we can check the behavior against bad signatures

	// static plaintext message
	let message = b"a message to authenticate";
	// dummy signature full of zeroes
	let bad_signature = vec![0; 64];
	// this should never succeed
	assert!(pubkey_special.verify(message, &bad_signature).is_err());

	let re_exported_public_key_data = pubkey_special.to_bytes();
	assert_eq!(data, re_exported_public_key_data);
});
