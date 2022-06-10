// TODO: Audit encryption strategy
// This file implements an envelope encryption strategy using RSA and AES 256
// CBC Ensure that this is a sensible approach.
// Should we use AES 256 CBC?
// Is there a better envelope encryption strategy to use? Something native to
// OpenSSL?

// TODO build out utilties for
// - converting private -> pub
// - private wraps most methods for pub ... like encrypt etc

use std::{
	fs::File,
	io::{Read, Write},
	ops::Deref,
	path::Path,
};

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

/// Standard length for QuorumOS RSA keys, specified in bits.
pub const RSA_KEY_LEN: u32 = 4096;

#[derive(Debug)]
pub enum CryptoError {
	IOError(std::io::Error),
	OpenSSLError(openssl::error::ErrorStack),
	DecryptError(openssl::error::ErrorStack),
	InvalidEnvelope,
	EncryptionPayloadTooBig,
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
	public_key: RsaPub,
}

impl RsaPair {
	pub fn generate() -> Result<Self, CryptoError> {
		Rsa::generate(RSA_KEY_LEN)?.try_into()
	}

	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let mut content = Vec::new();
		let mut file = File::open(path)?;
		file.read_to_end(&mut content)?;
		let private_key = Rsa::private_key_from_pem(&content[..])?;

		private_key.try_into()
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

	pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let mut to = vec![0; self.private_key.size() as usize];
		let size = self.private_key.private_decrypt(
			data,
			&mut to,
			Padding::PKCS1_OAEP,
		)?;

		Ok(to[0..size].to_vec())
	}

	pub fn envelope_decrypt(
		&self,
		data: &[u8],
	) -> Result<Vec<u8>, CryptoError> {
		let envelope: Envelope = serde_cbor::from_slice(&data[..])
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

	/// Exactly the same as [`RsaPub::encrypt`] executed with this pairs public
	/// key.
	pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
		self.public_key.encrypt(data)
	}

	/// Envelope encrypt using the RsaPair's associated RsaPub
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

pub struct RsaPub {
	public_key: Rsa<Public>,
}

impl RsaPub {
	pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
		let mut content = Vec::new();
		let mut file = File::open(path)?;
		file.read_to_end(&mut content)?;

		Self::from_pem(&content[..])
	}

	pub fn from_pem(pem: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { public_key: Rsa::public_key_from_pem(pem)? })
	}

	pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
		Ok(Self { public_key: Rsa::public_key_from_der(der)? })
	}

	pub fn write_pem_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), CryptoError> {
		let bytes = self.public_key.public_key_to_pem()?;
		let mut file = File::create(path)?;
		file.write_all(&bytes)?;
		Ok(())
	}

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
	pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let public_key_size = self.public_key.size() as usize;
		// TODO: WTF?
		if data.len() > public_key_size - 42 {
			return Err(CryptoError::EncryptionPayloadTooBig)
		}

		let mut to = vec![0; public_key_size];

		let size = self.public_key.public_encrypt(
			data,
			&mut to,
			Padding::PKCS1_OAEP,
		)?;

		Ok(to[0..size].to_vec())
	}

	pub fn envelope_encrypt(
		&self,
		data: &[u8],
	) -> Result<Vec<u8>, CryptoError> {
		let cipher = Cipher::aes_256_cbc();
		let key = {
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

		let encrypted_data = symm::encrypt(cipher, &key, Some(&iv), &data)?;
		let encrypted_symm_key = self.encrypt(&key)?;

		let envelope = Envelope { encrypted_data, encrypted_symm_key, iv };
		Ok(serde_cbor::to_vec(&envelope)
			.expect("`Envelope` impls cbor serialization"))
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

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
	pub encrypted_symm_key: Vec<u8>,
	pub encrypted_data: Vec<u8>,
	pub iv: Vec<u8>,
}

impl TryFrom<PKey<Private>> for RsaPub {
	type Error = CryptoError;
	fn try_from(pkey: PKey<Private>) -> Result<Self, Self::Error> {
		let pem = pkey.public_key_to_pem()?;
		let public_key = Rsa::public_key_from_pem(&pem[..])?;
		Ok(Self { public_key })
	}
}

/// Create a SHA256 hash digest of `buf`.
pub fn sha_256(buf: &[u8]) -> [u8; 32] {
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
	fn rsa_pair_encrypt() {
		let pair = RsaPair::generate().unwrap();

		let oversize = vec![u8::MAX; pair.size() as usize - 41];
		assert!(pair.encrypt(&oversize).is_err());

		// TODO: WTF?
		let perfect_size = vec![u8::MAX; pair.size() as usize - 42];
		let encrypted = pair.encrypt(&perfect_size).unwrap();
		let decrypted = pair.decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, perfect_size);

		let smaller_size = vec![u8::MAX; pair.size() as usize - 43];
		let encrypted = pair.encrypt(&smaller_size).unwrap();
		let decrypted = pair.decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, smaller_size);
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
		let private = Rsa::generate(4096).unwrap();

		let public_key =
			RsaPub::from_der(&private.public_key_to_der().unwrap()).unwrap();
		let envelope = public_key.envelope_encrypt(data).unwrap();

		let pair: RsaPair = private.try_into().unwrap();
		// let decrypted = pair.envelope_decrypt(&envelope);
		let decrypted = pair.envelope_decrypt(&envelope).unwrap();

		assert_eq!(data.to_vec(), decrypted);
	}

	#[test]
	fn e2e_rsa_crypto() {
		let data = b"small data";
		let private = Rsa::generate(4096).unwrap();
		let public_key =
			RsaPub::from_der(&private.public_key_to_der().unwrap()).unwrap();
		let encrypted = public_key.encrypt(data).unwrap();

		let pair: RsaPair = private.try_into().unwrap();
		let decrypted = pair.decrypt(&encrypted).unwrap();

		assert_eq!(data.to_vec(), decrypted);
	}
}
