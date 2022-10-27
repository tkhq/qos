use std::str;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::prelude::*;
use rand_core::OsRng;
use sha2::Digest;
use aes_gcm::{
	aead::{Aead, KeyInit, OsRng as AesOsRng},
	Aes256Gcm, Nonce // Or `Aes128Gcm`
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const MESSAGE: &[u8] = b"plaintext super secret message";

fn generate_pair() -> (EncodedPoint, PublicKey, EphemeralSecret) {
	let private = EphemeralSecret::random(&mut OsRng);
	let encoded_point = EncodedPoint::from(private.public_key());
	let public = PublicKey::from_sec1_bytes(encoded_point.as_ref())
		.expect("Bob's public key invalid");

	(encoded_point, public, private)
}

struct AdditionalAuthenticatedData {
	nonce: Vec<u8>,
	// send_pub_key: Vec<u8>,
	pub_key_one: Vec<u8>,

}

struct Envelope {
	additional_authenticated_data: AdditionalAuthenticatedData,
}

fn main() {
	let (alice_private_ep, alice_public, alice_private) = generate_pair();

	let (bob_private_ep, bob_public, bob_private) = generate_pair();

	// Alice and bob agree on a shared one-time-use number as an initialization
	// vector, or nonce.
	let iv = rand::thread_rng().gen::<[u8; 16]>();

	// Bob generates a shared secret using Alice's public key via Diffie Hellman
	let bob_shared_secret = bob_private.diffie_hellman(&alice_public);

	// Bob generates a shared AES key from this shared secret with the shared IV
	let bob_shared_key = sha2::Sha512::digest(bob_shared_secret.raw_secret_bytes()).to_vec();
	let bob_cipher = Aes256Gcm::new_from_slice(&bob_shared_key[..32]).unwrap();

	let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
	let hash = sha2::Sha512::digest(random_bytes).to_vec();
	let nonce = 	Nonce::from_slice(&hash[..12]);
	let encrypted_message = bob_cipher.encrypt(nonce, MESSAGE).unwrap();



	// Alice derives the same shared secret as Bob
	let alice_shared_secret = alice_private.diffie_hellman(&bob_public);

	// Alice generates the same AES key as Bob from this shared secret and the
	// shared IV
	let alice_shared_key = sha2::Sha512::digest(alice_shared_secret.raw_secret_bytes()).to_vec();

	let alice_cipher = Aes256Gcm::new_from_slice(&alice_shared_key[..32]).unwrap();
	let decrypted_message = alice_cipher.decrypt(nonce, &encrypted_message[..]).unwrap();

	// Alice decrypts Bob's message

	println!(
		"\nAlice public key {:x?}",
		qos_hex::encode(alice_private_ep.as_ref())
	);
	println!(
		"\nBob public key {:x?}",
		qos_hex::encode(bob_private_ep.as_ref())
	);
	println!("\nEncrypted message: {:?}", qos_hex::encode(&encrypted_message));
	println!(
		"\nDecrypted message: {:?}",
		str::from_utf8(&decrypted_message).unwrap()
	);
}
