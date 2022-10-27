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

#[derive(
	Debug, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, PartialEq,
)]
struct Envelope {
	nonce: Vec<u8>,
	/// Public key as sec1 encoded point with no compression
	ephemeral_pub_key: Vec<u8>,
	/// The data encrypted to the symmetrical key
	encrypted_message: Vec<u8>,
}

struct P256Pair {
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
		let Envelope { nonce, ephemeral_pub_key, encrypted_message } =
			Envelope::try_from_slice(serialized_envelope).unwrap();

		let nonce = Nonce::from_slice(&nonce);
		let ephemeral_pub_key =
			PublicKey::from_sec1_bytes(&ephemeral_pub_key).unwrap();

		let shared_secret = self.private.diffie_hellman(&ephemeral_pub_key);
		let shared_key = sha2::Sha512::digest(shared_secret.raw_secret_bytes());
		let cipher =
			Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN]).unwrap();

		cipher.decrypt(nonce, &*encrypted_message).unwrap()
	}
}

struct P256Public {
	public_key: PublicKey,
}

impl P256Public {
	// TODO: make this fallible and remove panics.
	pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
		let eph_private = EphemeralSecret::random(&mut OsRng);
		let eph_public_key = eph_private.public_key();

		let shared_secret = eph_private.diffie_hellman(&self.public_key);
		let shared_key = sha2::Sha512::digest(shared_secret.raw_secret_bytes());
		let cipher =
			Aes256Gcm::new_from_slice(&shared_key[..AES256_KEY_LEN]).unwrap();

		let nonce = {
			let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
			*Nonce::from_slice(&random_bytes[..12])
		};

		// TODO: use nonce||ephemeral_pub_key as authenticated data .. although
		// doesn't seem strictly necessary
		let encrypted_message = cipher.encrypt(&nonce, message).unwrap();

		let envelope = Envelope {
			encrypted_message,
			nonce: nonce.to_vec(),
			ephemeral_pub_key: eph_public_key
				.to_encoded_point(false)
				.as_ref()
				.to_vec(),
		};

		envelope.try_to_vec().unwrap()
	}
}

impl From<&P256Pair> for P256Public {
	fn from(pair: &P256Pair) -> Self {
		Self { public_key: pair.private.public_key() }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn basic_encrypt_decrypt() {
		let alice_pair = P256Pair::generate();
		let alice_public = P256Public::from(&alice_pair);

		let plaintext = b"rust test message";

		let serialized_envelope = alice_public.encrypt(plaintext);

		let decrypted = alice_pair.decrypt(&serialized_envelope);

		assert_eq!(decrypted, plaintext);
	}
}
