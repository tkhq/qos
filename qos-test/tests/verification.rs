#[test]
fn rsa_verify_payload() {
	// - Load a file (executable) ++ signatures
	// - Verify each signature with known public keys

	// Load RSA Pub key
	let pub_key = RsaPub::from_file("path to file");

	// Verify by hashing the payload
	pub_key.verify("payload")
	// OR verify the pre-hashed payload
	// pub_key.verify_raw(hash("payload"))
}
