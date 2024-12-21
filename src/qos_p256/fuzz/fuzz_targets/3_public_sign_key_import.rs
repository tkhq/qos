#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPublic;

// this harness is partially based on the public_key_round_trip_bytes_works() unit test
// it is a simpler variant of another public key import harness

fuzz_target!(|data: &[u8]| {
	// let the fuzzer control the P256 signing pubkey

	// import public key from bytes, silently exit in case of errors
	let pubkey_special = match P256SignPublic::from_bytes(data) {
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
    // the exported data doesn't actually have to be identical to initial input,
    // since P256SignPublic::from_bytes() accepts compressed points as well
    // 
    // workaround: compare only the 32 data bytes corresponding to the first sub-point,
    // ignoring the first format byte and any trailing data
    assert_eq!(data[1..33], re_exported_public_key_data[1..33]);
});
