mod shamir;
use std::{
	fs::File,
	io::{Read, Write},
	path::Path,
};

use openssl::{
	hash::MessageDigest,
	pkey::{PKey, Private, Public},
	rsa::Rsa,
	sign::{Signer, Verifier},
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
	pub_key: Rsa<Public>,
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
		verifier.verify_oneshot(signature, msg).map_err(Into::into)
	}
}

impl TryFrom<PKey<Private>> for RsaPub {
	type Error = CryptoError;
	fn try_from(pkey: PKey<Private>) -> Result<Self, Self::Error> {
		let pem = pkey.public_key_to_pem()?;
		let pub_key = Rsa::public_key_from_pem(&pem[..])?;
		Ok(Self { pub_key })
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
}
