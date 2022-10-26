use std::str;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::prelude::*;
use rand_core::OsRng;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn main() {
	// Alice generates a random asymmetric keypair
	let alice_private = EphemeralSecret::random(&mut OsRng);
	let alice_private_ep = EncodedPoint::from(alice_private.public_key());
	let alice_public = PublicKey::from_sec1_bytes(alice_private_ep.as_ref())
		.expect("Alice's public key invalid");

	// Bob generates a random asymmetric keypair
	let bob_private = EphemeralSecret::random(&mut OsRng);
	let bob_private_ep = EncodedPoint::from(bob_private.public_key());
	let bob_public = PublicKey::from_sec1_bytes(bob_private_ep.as_ref())
		.expect("Bob's public key invalid");

	// Alice and bob agree on a shared one-time-use number as an initialization
	// vector, or nonce.
	let iv = rand::thread_rng().gen::<[u8; 16]>();

	// Bob generates a shared secret using Alice's public key via Diffie Hellman
	let bob_shared_secret = bob_private.diffie_hellman(&alice_public);

	// Bob generates a shared AES key from this shared secret with the shared IV
	let bob_shared_key = bob_shared_secret.raw_secret_bytes();
	let bob_shared_cipher =
		Aes256Cbc::new_from_slices(&bob_shared_key, &iv).unwrap();

	// Bob encrypts a secret to Alice with the shared AES key
	let message_str = String::from("Secret message");
	let message = message_str.as_bytes();
	let mut message_buffer = [0u8; 128];
	message_buffer[..message.len()].copy_from_slice(message);
	let encrypted_message =
		bob_shared_cipher.encrypt(&mut message_buffer, message.len()).unwrap();

	// Alice derives the same shared secret as Bob
	let alice_shared_secret = alice_private.diffie_hellman(&bob_public);

	// Alice generates the same AES key as Bob from this shared secret and the
	// shared IV
	let alice_shared_key = alice_shared_secret.raw_secret_bytes();
	let alice_shared_cipher =
		Aes256Cbc::new_from_slices(&alice_shared_key, &iv).unwrap();

	// Alice decrypts Bob's message
	let mut encrypted_message_vec = encrypted_message.to_vec();
	let decrypted_message =
		alice_shared_cipher.decrypt(&mut encrypted_message_vec).unwrap();

	println!(
		"\nAlice public key {:x?}",
		qos_hex::encode(alice_private_ep.as_ref())
	);
	println!("\nBob public key {:x?}", qos_hex::encode(bob_private_ep.as_ref()));
	println!("\nEncrypted message: {:?}", qos_hex::encode(encrypted_message));
	println!(
		"\nDecrypted message: {:?}",
		str::from_utf8(decrypted_message).unwrap()
	);
}
