mod shamir;
pub use shamir::*;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

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

pub fn load_public_key(path: String) -> Result<Rsa<Public>, CryptoError> {
	let mut content = Vec::new();
	let mut file = File::open(path)?;
	file.read_to_end(&mut content)?;
	let pk = Rsa::public_key_from_pem(&content[..])?;
	Ok(pk)
}

pub fn write_public_key(
	path: String,
	key: Rsa<Public>,
) -> Result<(), CryptoError> {
	let bytes = key.public_key_to_pem()?;
	let mut file = File::create(path)?;
	file.write_all(&bytes)?;
	Ok(())
}

pub fn sign_with_key(
	key: Rsa<Private>,
	message: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
	let keypair = PKey::from_rsa(key)?;
	let mut signer = Signer::new(MessageDigest::sha256(), &keypair)?;
	signer.update(&message)?;
	let signature = signer.sign_to_vec()?;
	Ok(signature)
}

pub struct RsaPub {
	pub_key: Rsa<Public>,
}

impl RsaPub {
	pub fn from_pem_file<P>(path: P) -> Result<Self, CryptoError>
	where
		P: AsRef<Path>,
	{
		let mut content = Vec::new();
		let mut file = File::open(path)?;
		file.read_to_end(&mut content)?;

		Ok(Self { pub_key: Rsa::public_key_from_pem(&content[..])? })
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

// END GOAL
// - inside the enclave, asses if a particular file has been approved
//  based on RSA keys
// - read in file and verify signature
// - have trusted RSA keys on disk

// Pivot
// - executable: binary on enclave sent over message endpoints (payload ++ signatures)
//   - cli: allow to send random bytes
// - pivot: check that file and included signatures actually works

// Load in public key from a file (for now...)
// Verify a signature with public key
// (Test): Generate an RSA key
// (Test): Sign with an RSA key

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn rsa_pub_from_pem_file() {
		// cur-dir/mock/rsa_public.mock.pem
		let mut path = std::env::current_dir().unwrap();
		path.push("mock");
		path.push("rsa_public.mock.pem");

		let _pub_key = RsaPub::from_pem_file(path.clone()).unwrap();
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
}
