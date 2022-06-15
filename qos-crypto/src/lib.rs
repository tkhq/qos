//! Cryptographic primitves for use with `QuorumOS`.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

// TODO: Audit encryption strategy
// This file implements an envelope encryption strategy using RSA and AES 256
// CBC Ensure that this is a sensible approach.
// Should we use AES 256 CBC?
// Is there a better envelope encryption strategy to use? Something native to
// OpenSSL?

use std::{fs::File, io::Write, ops::Deref, path::Path};

use borsh::{BorshDeserialize, BorshSerialize};
use openssl::{
	hash::MessageDigest,
	pkey::{PKey, Private, Public},
	rand,
	rsa::{Padding, Rsa},
	sign::{Signer, Verifier},
	symm::{self, Cipher},
};

mod shamir;

pub use shamir::*;

/// Standard length for `QuorumOS` RSA keys, specified in bits.
pub const RSA_KEY_LEN: u32 = 4096;

/// Errors for this crate.
#[derive(Debug)]
pub enum CryptoError {
	/// Wrapper for `std::io::Error`.
	IOError(std::io::Error),
	/// Wrapper for `openssl::error::ErrorStack`.
	OpenSSLError(openssl::error::ErrorStack),
	/// Error while trying to decrypt.
	DecryptError(openssl::error::ErrorStack),
	/// An `Envelope` could not be deserialized.
	InvalidEnvelope,
	/// Cannot encrypt a payload because it is too big.
	EncryptionPayloadTooBig,
}

impl From<std::io::Error> for CryptoError {
	fn from(err: std::io::Error) -> Self {
		Self::IOError(err)
	}
}

impl From<openssl::error::ErrorStack> for CryptoError {
	fn from(_err: openssl::error::ErrorStack) -> Self {
		Self::OpenSSLError(openssl::error::ErrorStack::get())
	}
}

/// Create a SHA256 hash digest of `buf`.
#[must_use]
pub fn sha_256(buf: &[u8]) -> [u8; 32] {
	let mut hasher = openssl::sha::Sha256::new();
	hasher.update(buf);
	hasher.finish()
}

/// RSA Private key pair.
#[derive(Clone)]
pub struct RsaPair {
	private_key: Rsa<Private>,
	public_key: RsaPub,
}

impl RsaPair {
	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> &RsaPub {
		&self.public_key
	}

	/// Generate a new 4096 RSA key pair.
	pub fn generate() -> Result<Self, CryptoError> {
		Rsa::generate(RSA_KEY_LEN)?.try_into()
	}

	/// Create [`Self`] from a file that has a PEM encoded RSA private key.
	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let content = std::fs::read(path)?;
		let private_key = Rsa::private_key_from_pem(&content[..])?;
		private_key.try_into()
	}

	/// Create [`Self`] from a PEM encoded RSA private key.
	pub fn from_pem(data: &[u8]) -> Result<Self, CryptoError> {
		let private_key = Rsa::private_key_from_pem(data)?;
		private_key.try_into()
	}

	/// Create [`Self`] from a DER encoded RSA private key.
	pub fn from_der(data: &[u8]) -> Result<Self, CryptoError> {
		let private_key = Rsa::private_key_from_der(data)?;
		private_key.try_into()
	}

	/// Sign the sha256 digest of `msg`. Returns the signature as a byte vec.
	pub fn sign_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let pkey = PKey::from_rsa(self.private_key.clone())?;
		let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
		signer.update(msg)?;
		signer.sign_to_vec().map_err(Into::into)
	}

	/// Get the PEM encoded private key.
	pub fn public_key_pem(&self) -> Result<Vec<u8>, CryptoError> {
		self.private_key.public_key_to_pem().map_err(Into::into)
	}

	// RSA decrypt. Should never be used on arbitrary data directly. Instead
	// always prefer [`Self::envelope_decrypt`].
	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let mut to = vec![0; self.private_key.size() as usize];
		let size = self.private_key.private_decrypt(
			data,
			&mut to,
			Padding::PKCS1_OAEP,
		)?;

		Ok(to[0..size].to_vec())
	}

	/// Decrypt envelope encrypted `data`. Also see [`Self::envelope_encrypt`].
	pub fn envelope_decrypt(
		&self,
		data: &[u8],
	) -> Result<Vec<u8>, CryptoError> {
		let envelope: Envelope = Envelope::try_from_slice(data)
			.map_err(|_| CryptoError::InvalidEnvelope)?;
		let key = self.decrypt(&envelope.encrypted_symm_key)?;
		let cipher = Cipher::aes_256_cbc();

		symm::decrypt(
			cipher,
			&key,
			Some(&envelope.iv),
			&envelope.encrypted_data,
		)
		.map_err(CryptoError::from)
	}

	/// Envelope encrypt using the `RsaPair`'s associated `RsaPub`
	pub fn envelope_encrypt(
		&self,
		data: &[u8],
	) -> Result<Vec<u8>, CryptoError> {
		self.public_key.envelope_encrypt(data)
	}
}

impl TryFrom<PKey<Private>> for RsaPair {
	type Error = CryptoError;
	fn try_from(private_key: PKey<Private>) -> Result<Self, Self::Error> {
		let private_key = private_key.rsa()?;
		let public_key = RsaPub::try_from(&private_key)?;
		Ok(Self { private_key, public_key })
	}
}

impl TryFrom<Rsa<Private>> for RsaPair {
	type Error = CryptoError;
	fn try_from(private_key: Rsa<Private>) -> Result<Self, Self::Error> {
		let public_key = RsaPub::try_from(&private_key)?;
		Ok(Self { private_key, public_key })
	}
}

impl Deref for RsaPair {
	type Target = Rsa<Private>;

	fn deref(&self) -> &Self::Target {
		&self.private_key
	}
}

/// RSA public key.
#[derive(Debug, Clone)]
pub struct RsaPub {
	public_key: Rsa<Public>,
}

impl RsaPub {
	/// Create [`Self`] from a PEM encoded RSA public key from a file.
	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let content = std::fs::read(path)?;
		Self::from_pem(&content[..])
	}

	/// Create [`Self`] from a PEM encoded RSA public key.
	pub fn from_pem(pem: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { public_key: Rsa::public_key_from_pem(pem)? })
	}

	/// Create [`Self`] from a DER encoded RSA public key.
	pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { public_key: Rsa::public_key_from_der(der)? })
	}

	/// Write the PEM encoded public key to file.
	pub fn write_pem_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), CryptoError> {
		let bytes = self.public_key.public_key_to_pem()?;
		let mut file = File::create(path)?;
		file.write_all(&bytes)?;
		Ok(())
	}

	/// Verify the signature over the SHA-256 digest of `msg`.
	pub fn verify_sha256(
		&self,
		signature: &[u8],
		msg: &[u8],
	) -> Result<bool, CryptoError> {
		let public = PKey::from_rsa(self.public_key.clone())?;
		let mut verifier = Verifier::new(MessageDigest::sha256(), &public)?;
		verifier.update(msg)?;
		verifier.verify(signature).map_err(Into::into)
	}

	/// Encrypt the given `data` to the RSA public key.
	///
	/// If the size of the `data` can be greater then or equal to the RSA public
	/// key use [`Self::envelope_encrypt`]
	///
	/// # Error
	///
	/// Errors if the `data` is bigger then the public key.
	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let public_key_size = self.public_key.size() as usize;
		// TODO: WTF?
		if data.len() > public_key_size - 42 {
			return Err(CryptoError::EncryptionPayloadTooBig);
		}

		let mut to = vec![0; public_key_size];

		let size = self.public_key.public_encrypt(
			data,
			&mut to,
			Padding::PKCS1_OAEP,
		)?;

		Ok(to[0..size].to_vec())
	}

	/// Encrypt `data` using envelope encryption. The data is encrypted with AES
	/// 256 CBC, a symmetric encryption key. The AES 256 CBC key is encrypted
	/// with this public RSA key.
	pub fn envelope_encrypt(
		&self,
		data: &[u8],
	) -> Result<Vec<u8>, CryptoError> {
		let cipher = Cipher::aes_256_cbc();
		let key = {
			// TODO: better entropy?
			let mut buf = vec![0; cipher.key_len()];
			rand::rand_bytes(buf.as_mut_slice())?;
			buf
		};

		let iv = {
			let mut buf =
				vec![0; cipher.iv_len().expect("AES 256 CBC has an IV")];
			rand::rand_bytes(buf.as_mut_slice())?;
			buf
		};

		let encrypted_data = symm::encrypt(cipher, &key, Some(&iv), data)?;
		let encrypted_symm_key = self.encrypt(&key)?;

		let envelope = Envelope { encrypted_symm_key, encrypted_data, iv };
		Ok(envelope.try_to_vec().expect("`Envelope` impls serialization"))
	}
}

impl Deref for RsaPub {
	type Target = Rsa<Public>;

	fn deref(&self) -> &Self::Target {
		&self.public_key
	}
}

impl From<Rsa<Public>> for RsaPub {
	fn from(public_key: Rsa<Public>) -> Self {
		Self { public_key }
	}
}

impl From<RsaPair> for RsaPub {
	fn from(pair: RsaPair) -> Self {
		Self { public_key: pair.public_key.public_key }
	}
}

impl TryFrom<&Rsa<Private>> for RsaPub {
	type Error = CryptoError;
	fn try_from(private_key: &Rsa<Private>) -> Result<Self, Self::Error> {
		Self::from_der(&private_key.public_key_to_der()?)
	}
}

impl PartialEq for RsaPub {
	fn eq(&self, other: &Self) -> bool {
		self.public_key_to_der().expect("RsaPub can DER-encode")
			== other.public_key_to_der().expect("RsaPub can DER-encode")
	}
}

#[derive(PartialEq, Debug, Clone, BorshSerialize, BorshDeserialize)]
struct Envelope {
	pub encrypted_symm_key: Vec<u8>,
	pub encrypted_data: Vec<u8>,
	pub iv: Vec<u8>,
}

impl TryFrom<PKey<Private>> for RsaPub {
	type Error = CryptoError;
	fn try_from(pkey: PKey<Private>) -> Result<Self, Self::Error> {
		let der = pkey.public_key_to_der()?;
		let public_key = Rsa::public_key_from_der(&der[..])?;
		Ok(Self { public_key })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn rsa_pub_from_pem_file() {
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_public.mock.pem");

		let _public_key = RsaPub::from_pem_file(path.clone()).unwrap();
	}

	#[test]
	fn rsa_pair_from_pem_file() {
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_private.mock.pem");

		let _pair = RsaPair::from_pem_file(path.clone()).unwrap();
	}

	#[test]
	fn rsa_pub_encrypt() {
		let pair = RsaPair::generate().unwrap();
		let public = RsaPub::try_from(&*pair).unwrap();

		let oversize = vec![u8::MAX; public.size() as usize - 41];
		assert!(public.encrypt(&oversize).is_err());

		// TODO: WTF?
		let perfect_size = vec![u8::MAX; public.size() as usize - 42];
		let encrypted = public.encrypt(&perfect_size).unwrap();
		let decrypted = pair.decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, perfect_size);

		let smaller_size = vec![u8::MAX; public.size() as usize - 43];
		let encrypted = public.encrypt(&smaller_size).unwrap();
		let decrypted = pair.decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, smaller_size);
	}

	#[test]
	fn e2e_crypto() {
		let pair = RsaPair::generate().unwrap();
		let data = b"vape nation";
		let signature = pair.sign_sha256(data).unwrap();
		assert!(pair.public_key().verify_sha256(&signature, data).unwrap());
	}

	#[test]
	fn e2e_crypto_from_pem_file() {
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_private.mock.pem");

		let pair = RsaPair::from_pem_file(path.clone()).unwrap();

		let msg = &mut b"vape nation".to_vec()[..];

		let signature = pair.sign_sha256(msg).unwrap();

		let pub_pem = pair.public_key_pem().unwrap();
		let rsa_pub: RsaPub = RsaPub::from_pem(&pub_pem[..]).unwrap();
		assert!(rsa_pub.verify_sha256(&signature, msg).unwrap());
	}

	#[test]
	fn e2e_envelope_crypto_private_key() {
		let data = b"a nation that vapes big puffy clouds";
		let private = RsaPair::generate().unwrap();
		let envelope = private.envelope_encrypt(data).unwrap();
		let decrypted = private.envelope_decrypt(&envelope).unwrap();

		assert_eq!(data.to_vec(), decrypted);
	}

	#[test]
	fn e2e_envelope_crypto_public_key() {
		let data = b"a nation that vapes big puffy clouds";
		let private = RsaPair::generate().unwrap();
		let public: RsaPub = private.clone().try_into().unwrap();
		let envelope = public.envelope_encrypt(data).unwrap();
		let decrypted = private.envelope_decrypt(&envelope).unwrap();

		assert_eq!(data.to_vec(), decrypted);
	}
}
