//! Abstractions for authentication and encryption with NIST-P256.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod encrypt;
pub mod sign;

/// Errors for qos P256.
#[derive(Debug, PartialEq)]
pub enum P256Error {
	/// The encryption envelope should not be serialized. This is likely a bug
	/// with the code.
	FailedToSerializeEnvelope,
	/// The encryption envelope could not be deserialized.
	FailedToDeserializeEnvelope,
	/// An error while decrypting the ciphertext with the `AesGcm256` cipher.
	AesGcm256DecryptError,
	/// An error while encrypting the plaintext with the `AesGcm256` cipher.
	AesGcm256EncryptError,
	/// Failed to create the `AesGcm256` cipher.
	FailedToCreateAes256GcmCipher,
	/// The public key could not be deserialized.
	FailedToDeserializePublicKey,
	/// Public Key could not be coerced into the intended length.
	FailedToCoercePublicKeyToIntendedLength,
	/// Nonce could not be coerced into the intended length.
	FailedToCoerceNonceToIntendedLength,
	/// Signature could not be de-serialized as DER encoded.
	FailedToDeserializeSignatureAsDer,
	/// The signature could not be verified against the given message and
	/// public key.
	FailedSignatureVerification,
	/// Could not deserialize a public key as `SEC1` encoded.
	FailedToDeserializePublicKeyFromSec1,
	/// The raw bytes could not be interpreted as a P256 secret.
	FailedToReadSecret,
}
