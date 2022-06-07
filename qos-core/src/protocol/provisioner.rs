use std::{fs::File, io::Write};

use super::ProtocolError;

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

pub struct SecretProvisioner {
	shares: Shares,
	pub secret: Option<Secret>,
	secret_file: String,
}

impl SecretProvisioner {
	pub fn new(secret_file: String) -> Self {
		Self { shares: Vec::new(), secret: None, secret_file }
	}

	pub fn add_share(&mut self, share: Share) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}

		self.shares.push(share);
		Ok(())
	}

	pub fn reconstruct(&mut self) -> Result<Secret, ProtocolError> {
		let secret = qos_crypto::shares_reconstruct(&self.shares);

		// TODO: Add better validation...
		if secret.is_empty() {
			return Err(ProtocolError::ReconstructionError);
		}

		// TODO: Make errors more specific...
		let mut file = File::create(&self.secret_file)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		file.write_all(&secret)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		Ok(secret)
	}
}
