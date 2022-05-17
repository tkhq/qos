mod shamir;
use std::{
	fs::File,
	io::{Read, Write},
};

use openssl::{
	hash::MessageDigest,
	pkey::{PKey, Private, Public},
	rsa::Rsa,
	sign::Signer,
};
pub use shamir::*;

pub enum CryptographyError {
	IOError(std::io::Error),
	OpenSSLError(openssl::error::ErrorStack),
}

impl From<std::io::Error> for CryptographyError {
	fn from(err: std::io::Error) -> Self {
		CryptographyError::IOError(err)
	}
}

impl From<openssl::error::ErrorStack> for CryptographyError {
	fn from(_: openssl::error::ErrorStack) -> Self {
		CryptographyError::OpenSSLError(openssl::error::ErrorStack::get())
	}
}

pub fn load_public_key(path: String) -> Result<Rsa<Public>, CryptographyError> {
	let mut content = Vec::new();
	let mut file = File::open(path)?;
	file.read_to_end(&mut content)?;
	let pk = Rsa::public_key_from_pem(&content[..])?;
	Ok(pk)
}

pub fn write_public_key(
	path: String,
	key: Rsa<Public>,
) -> Result<(), CryptographyError> {
	let bytes = key.public_key_to_pem()?;
	let mut file = File::create(path)?;
	file.write_all(&bytes)?;
	Ok(())
}

pub fn sign_with_key(
	key: Rsa<Private>,
	message: Vec<u8>,
) -> Result<Vec<u8>, CryptographyError> {
	let keypair = PKey::from_rsa(key)?;
	let mut signer = Signer::new(MessageDigest::sha256(), &keypair)?;
	signer.update(&message)?;
	let signature = signer.sign_to_vec()?;
	Ok(signature)
}

// Load in public key from a file (for now...)
// Verify a signature with public key
// (Test): Generate an RSA key
// (Test): Sign with an RSA key

#[cfg(test)]
mod test {
	use openssl::sign::Verifier;

	use super::*;

	#[test]
	fn e2e_crypto() {
		let rsa = Rsa::generate(4096).unwrap();
		let pair = PKey::from_rsa(rsa).unwrap();

		let data = b"vape nation";
		let mut signer = Signer::new(MessageDigest::sha256(), &pair).unwrap();
		signer.update(data);
		let signature = signer.sign_to_vec().unwrap();

		let mut verifier =
			Verifier::new(MessageDigest::sha256(), &pair).unwrap();
		verifier.update(data);
		assert!(verifier.verify(&signature).unwrap());
	}
}
