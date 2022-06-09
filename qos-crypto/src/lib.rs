// TODO: Audit encryption strategy
// This file implements an envelope encryption strategy using RSA and AES 256 CBC
// Ensure that this is a sensible approach.
// Should we use AES 256 CBC?
// Is there a better envelope encryption strategy to use? Something native to OpenSSL?

mod shamir;
use std::{
	fs::File,
	io::{Read, Write},
	path::Path,
};

use openssl::{
	hash::MessageDigest,
	pkey::{PKey, Private, Public},
	rsa::{Rsa, Padding},
	sign::{Signer, Verifier},
	symm::{self, Cipher},
	rand
};
pub use shamir::*;

#[derive(Debug)]
pub enum CryptoError {
	IOError(std::io::Error),
	OpenSSLError(openssl::error::ErrorStack),
}

impl From<std::io::Error> for CryptoError {
	fn from(err: std::io::Error) -> Self {
		CryptoError::IOError(err)
	}
}

impl From<openssl::error::ErrorStack> for CryptoError {
	fn from(_err: openssl::error::ErrorStack) -> Self {
		CryptoError::OpenSSLError(openssl::error::ErrorStack::get())
	}
}

/// RSA Private key pair.
pub struct RsaPair {
	private_key: Rsa<Private>,
}

impl RsaPair {
	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let mut content = Vec::new();
		let mut file = File::open(path)?;
		file.read_to_end(&mut content)?;

		Ok(Self { private_key: Rsa::private_key_from_pem(&content[..])? })
	}

	/// Sign the sha256 digest of `msg`. Returns the signature as a byte vec.
	pub fn sign_sha256(&self, msg: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
		let pkey = PKey::from_rsa(self.private_key.clone())?;
		let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
		signer.update(msg)?;
		signer.sign_to_vec().map_err(Into::into)
	}

	pub fn public_key_pem(&self) -> Result<Vec<u8>, CryptoError> {
		self.private_key.public_key_to_pem().map_err(Into::into)
	}

	pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
		let mut to = vec![0; self.private_key.size() as usize];
		let size = self.private_key.private_decrypt(data, &mut to, Padding::PKCS1_OAEP).expect("TODO");
		to[0..size].to_vec()
	}

	pub fn envelope_decrypt(&self, envelope: &Envelope) -> Vec<u8> {
		let key = self.decrypt(&envelope.encrypted_symm_key);
		let cipher = Cipher::aes_256_cbc();

		symm::decrypt(cipher, &key, Some(&envelope.iv), &envelope.encrypted_data).expect("TODO")
	}
}

impl TryFrom<PKey<Private>> for RsaPair {
	type Error = CryptoError;
	fn try_from(private_key: PKey<Private>) -> Result<Self, Self::Error> {
		Ok(Self { private_key: private_key.rsa()? })
	}
}

impl From<Rsa<Private>> for RsaPair {
	fn from(private_key: Rsa<Private>) -> Self {
		Self { private_key }
	}
}


pub struct RsaPub {
	pub pub_key: Rsa<Public>,
}

impl RsaPub {
	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let mut content = Vec::new();
		let mut file = File::open(path)?;
		file.read_to_end(&mut content)?;

		Self::from_pem(&content[..])
	}

	pub fn from_pem(pem: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { pub_key: Rsa::public_key_from_pem(pem)? })
	}

	pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { pub_key: Rsa::public_key_from_der(der)? })
	}

	pub fn write_pem_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), CryptoError> {
		let bytes = self.pub_key.public_key_to_pem()?;
		let mut file = File::create(path)?;
		file.write_all(&bytes)?;
		Ok(())
	}

	pub fn verify_sha256(
		&self,
		signature: &[u8],
		msg: &[u8],
	) -> Result<bool, CryptoError> {
		let public = PKey::from_rsa(self.pub_key.clone())?;
		let mut verifier = Verifier::new(MessageDigest::sha256(), &public)?;
		verifier.update(msg)?;
		verifier.verify(signature).map_err(Into::into)
	}

	/// # Panics
	///
	/// Panics if the payload is too big.
	pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
		let mut to = vec![0; self.pub_key.size() as usize];
		let size = self.pub_key.public_encrypt(data, &mut to, Padding::PKCS1_OAEP).expect("TODO");
		to[0..size].to_vec()
	}

	pub fn envelope_encrypt(&self, data: &[u8]) -> Envelope {
		let cipher = Cipher::aes_256_cbc();
		
		let key = {
			let mut buf = vec![0; cipher.key_len()];
			rand::rand_bytes(buf.as_mut_slice());
			buf
		};

		let iv = {
			let mut buf = vec![0; cipher.iv_len().expect("AES 256 CBC has an IV")];
			rand::rand_bytes(buf.as_mut_slice());
			buf
		};

		let encrypted_data = symm::encrypt(cipher, &key, Some(&iv), &data).expect("TODO");
		let encrypted_symm_key = self.encrypt(&key);

		Envelope { encrypted_data, encrypted_symm_key, iv }
	}
}

pub struct Envelope {
	pub encrypted_symm_key: Vec<u8>,
	pub encrypted_data: Vec<u8>,
	pub iv: Vec<u8>
}

impl TryFrom<PKey<Private>> for RsaPub {
	type Error = CryptoError;
	fn try_from(pkey: PKey<Private>) -> Result<Self, Self::Error> {
		let pem = pkey.public_key_to_pem()?;
		let pub_key = Rsa::public_key_from_pem(&pem[..])?;
		Ok(Self { pub_key })
	}
}

pub fn sha_256_hash(buf: &[u8]) -> [u8; 32] {
	let mut hasher = openssl::sha::Sha256::new();
	hasher.update(buf);
	hasher.finish()
}

#[cfg(test)]
mod test {
	use openssl::sign::Verifier;

	use super::*;

	#[test]
	fn rsa_pub_from_pem_file() {
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_public.mock.pem");

		let _pub_key = RsaPub::from_pem_file(path.clone()).unwrap();
	}

	#[test]
	fn rsa_pair_from_pem_file() {
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_private.mock.pem");

		let _pair = RsaPair::from_pem_file(path.clone()).unwrap();
	}

	#[test]
	fn e2e_crypto() {
		let rsa = Rsa::generate(4096).unwrap();
		let pair = PKey::from_rsa(rsa).unwrap();

		let data = b"vape nation";
		let mut signer = Signer::new(MessageDigest::sha256(), &pair).unwrap();
		signer.update(data).unwrap();
		let signature = signer.sign_to_vec().unwrap();

		let mut verifier =
			Verifier::new(MessageDigest::sha256(), &pair).unwrap();
		verifier.update(data).unwrap();
		assert!(verifier.verify(&signature).unwrap());

		let rsa_pub: RsaPub = pair.clone().try_into().unwrap();
		assert!(rsa_pub.verify_sha256(&signature, data).unwrap());
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
	fn e2e_envelope_crypto() {
		let data = b"a nation that vapes big puffy clouds";
		let pair = Rsa::generate(4096).unwrap();

		let pub_key = RsaPub::from_der(&pair.public_key_to_der().unwrap()).unwrap();
		let envelope = pub_key.envelope_encrypt(data);

		let priv_key: RsaPair = pair.into();
		let decrypted = priv_key.envelope_decrypt(&envelope);

		assert_eq!(data.to_vec(), decrypted);
	}

	#[test]
	fn e2e_rsa_crypto() {
		let data = b"small data";
		let pair = Rsa::generate(4096).unwrap();
		let pub_key = RsaPub::from_der(&pair.public_key_to_der().unwrap()).unwrap();
		let encrypted = pub_key.encrypt(data);

		let priv_key: RsaPair = pair.into();
		let decrypted = priv_key.decrypt(&encrypted);

		assert_eq!(data.to_vec(), decrypted);
	}
}
