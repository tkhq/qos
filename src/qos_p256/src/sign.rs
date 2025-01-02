//! Abstractions for sign and signature verification

use p256::ecdsa::{
	signature::{Signer, Verifier},
	Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

use crate::{P256Error, PUB_KEY_LEN_UNCOMPRESSED};

/// Sign private key pair.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct P256SignPair {
	/// The key used for signing
	pub(crate) private: SigningKey,
}

impl P256SignPair {
	/// Generate a new private key
	#[must_use]
	pub fn generate() -> Self {
		Self { private: SigningKey::random(&mut OsRng) }
	}

	/// Sign the message and return the. Signs the SHA512 digest of
	/// the message.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, P256Error> {
		let signature: Signature = self.private.sign(message);

		Ok(signature.to_vec())
	}

	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> P256SignPublic {
		P256SignPublic { public: VerifyingKey::from(&self.private) }
	}

	/// Deserialize key from raw scalar byte slice.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		Ok(Self {
			private: SigningKey::from_bytes(bytes)
				.map_err(|_| P256Error::FailedToReadSecret)?,
		})
	}

	/// Serialize key to raw scalar byte slice.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		self.private.to_bytes().to_vec()
	}
}

/// Sign public key for verifying signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct P256SignPublic {
	pub(crate) public: VerifyingKey,
}

impl P256SignPublic {
	/// Verify a `signature` and `message` against this private key. Verifies
	/// the SHA512 digest of the message.
	///
	/// Returns Ok if the signature is good.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), P256Error> {
		let signature = Signature::try_from(signature)
			.map_err(|_| P256Error::FailedToDeserializeSignature)?;

		self.public
			.verify(message, &signature)
			.map_err(|_| P256Error::FailedSignatureVerification)
	}

	/// Serialize to SEC1 encoded point, not compressed.
	#[must_use]
	pub fn to_bytes(&self) -> Box<[u8]> {
		let sec1_encoded_point = self.public.to_encoded_point(false);
		sec1_encoded_point.to_bytes()
	}

	/// Deserialize from a SEC1 encoded point, not compressed.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
		if bytes.len() > PUB_KEY_LEN_UNCOMPRESSED as usize {
			return Err(P256Error::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUB_KEY_LEN_UNCOMPRESSED as usize {
			return Err(P256Error::EncodedPublicKeyTooShort);
		}

		Ok(Self {
			public: VerifyingKey::from_sec1_bytes(bytes)
				.map_err(|_| P256Error::FailedToReadPublicKey)?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signatures_are_deterministic() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		(0..100)
			.map(|_| pair.sign(message).unwrap())
			.collect::<Vec<_>>()
			.windows(2)
			.for_each(|slice| assert_eq!(slice[0], slice[1]));
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let signature = pair.sign(message).unwrap();

		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signature() {
		let message = b"a message to authenticate";

		let alice_pair = P256SignPair::generate();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = P256SignPair::generate().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			P256Error::FailedSignatureVerification
		);
	}

	#[test]
	fn public_key_round_trip_bytes_works() {
		let message = b"a message to authenticate";

		let pair = P256SignPair::generate();
		let bytes_public = pair.public_key().to_bytes();
		let signature = pair.sign(message).unwrap();

		let public = P256SignPublic::from_bytes(&bytes_public).unwrap();

		assert!(public.verify(message, &signature).is_ok());
	}

	#[test]
	fn private_key_roundtrip_bytes_works() {
		let pair = P256SignPair::generate();
		let raw_secret1 = pair.to_bytes();

		let pair2 = P256SignPair::from_bytes(&raw_secret1).unwrap();
		let raw_secret2 = pair2.to_bytes();

		assert_eq!(raw_secret1, raw_secret2);
	}

	#[test]
	fn encoded_public_keys_bytes_are_validated() {
		let too_short = vec![0u8; 64];
		let too_long = vec![0u8; 66];

		// Uncompressed public key with a compressed prefix (0x02)
		let bad_prefix = qos_hex::decode("02bf772379de68fed2e81a47a141210c827c31fadc5b24ed3dafa84a9d19896172cb1b53ee6ecb38ca5c4be4d664b63f034886b764ad520c301fe542dfdf4002e4").unwrap();
		let just_right = qos_hex::decode("04bf772379de68fed2e81a47a141210c827c31fadc5b24ed3dafa84a9d19896172cb1b53ee6ecb38ca5c4be4d664b63f034886b764ad520c301fe542dfdf4002e4").unwrap();

		assert!(matches!(
			P256SignPublic::from_bytes(&too_short),
			Err(P256Error::EncodedPublicKeyTooShort)
		));
		assert!(matches!(
			P256SignPublic::from_bytes(&too_long),
			Err(P256Error::EncodedPublicKeyTooLong)
		));
		assert!(matches!(
			P256SignPublic::from_bytes(&bad_prefix),
			Err(P256Error::FailedToReadPublicKey),
		));
		assert!(matches!(P256SignPublic::from_bytes(&just_right), Ok(_),));
	}
}
