use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use p256::{
	ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey,
};
use rand::prelude::*;
use rand_core::OsRng;
use sha2::Digest;

const AES256_KEY_LEN: usize = 32;

// Helper function to create the `Aes256Gcm` cypher.
fn create_cipher(private: &EphemeralSecret, public: &PublicKey) -> Aes256Gcm {
	let shared_secret = private.diffie_hellman(public);
	let shared_key = sha2::Sha512::digest(shared_secret.raw_secret_bytes());
	Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN]).unwrap()
}

#[derive(
	Debug, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, PartialEq,
)]
struct Envelope {
	/// Nonce used as an input to the cipher.
	nonce: Vec<u8>,
	/// Public key as sec1 encoded point with no compression
	ephemeral_public: Vec<u8>,
	/// The data encrypted with an AES 256 GCM cipher.
	encrypted_message: Vec<u8>,
}

pub struct P256Pair {
	private: EphemeralSecret,
}

impl P256Pair {
	/// Generate a new private key using the OS randomness source.
	pub fn generate() -> Self {
		Self { private: EphemeralSecret::random(&mut OsRng) }
	}

	/// Decrypt a message encoded to this pair's public key.
	// TODO: make this fallible and remove panics.
	pub fn decrypt(&self, serialized_envelope: &[u8]) -> Vec<u8> {
		let Envelope { nonce, ephemeral_public, encrypted_message } =
			Envelope::try_from_slice(serialized_envelope).unwrap();

		let nonce = Nonce::from_slice(&nonce);
		let ephemeral_public =
			PublicKey::from_sec1_bytes(&ephemeral_public).unwrap();

		let cipher = create_cipher(&self.private, &ephemeral_public);

		cipher.decrypt(nonce, &*encrypted_message).unwrap()
	}

	pub fn public_key(&self) -> P256Public {
		P256Public { public_key: self.private.public_key() }
	}
}

pub struct P256Public {
	public_key: PublicKey,
}

impl P256Public {
	// TODO: make this fallible and remove panics.
	/// Encrypt a message to this public key.
	pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
		let ephemeral_private = EphemeralSecret::random(&mut OsRng);
		let ephemeral_public = ephemeral_private.public_key();

		let cipher = create_cipher(&ephemeral_private, &self.public_key);

		let nonce = {
			let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
			*Nonce::from_slice(&random_bytes[..12])
		};

		// TODO: use nonce||ephemeral_public as authenticated data .. although
		// doesn't seem strictly necessary
		let encrypted_message = cipher.encrypt(&nonce, message).unwrap();

		let envelope = Envelope {
			encrypted_message,
			nonce: nonce.to_vec(),
			ephemeral_public: ephemeral_public
				// TODO: Should we do compression? Is there a better way to
				// serialize the public key.
				.to_encoded_point(false)
				.as_ref()
				.to_vec(),
		};

		envelope.try_to_vec().unwrap()
	}

	// TODO: from der/sec1 etc
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn basic_encrypt_decrypt() {
		let alice_pair = P256Pair::generate();
		let alice_public = alice_pair.public_key();

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext);

		let decrypted = alice_pair.decrypt(&serialized_envelope);

		assert_eq!(decrypted, plaintext);
	}

	// What other edge cases should we test for?
}
