#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_p256::sign::P256SignPair;
use qos_p256::sign::P256SignPublic;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzKeyDataStruct {
	key: [u8; qos_p256::MASTER_SEED_LEN],
	data: Box<[u8]>,
}

// this harness is based on the public_key_round_trip_bytes_works() unit test

fuzz_target!(|input: FuzzKeyDataStruct| {
	// Let the fuzzer pick a P256 key
	let keypair = match P256SignPair::from_bytes(&input.key) {
		Ok(pair) => pair,
		Err(_err) => {
			return;
		}
	};

	// create valid signature
	let signature = keypair.sign(&input.data).unwrap();

	// derive public key and export it to bytes
	let bytes_public = keypair.public_key().to_bytes();

	// re-import public key from bytes
	// this should always succeed
	let public_reimported = P256SignPublic::from_bytes(&bytes_public)
		.expect("We just generated and exported this pubkey");

	assert!(keypair.public_key().verify(&input.data, &signature).is_ok());
	// expect the signature verification with the reconstructed pubkey to always succeed
	assert!(public_reimported.verify(&input.data, &signature).is_ok());

    let mut wrong_signature = signature.clone();
    let wrong_signature_last_element_index = wrong_signature.len() - 1;
    // flip a bit in the signature
    wrong_signature[wrong_signature_last_element_index] = wrong_signature[wrong_signature_last_element_index] ^ 1;
    // expect the verification to fail since the signature is bad
    assert!(public_reimported.verify(&input.data, &wrong_signature).is_err());
});
