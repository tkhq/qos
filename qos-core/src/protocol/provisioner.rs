use std::{fs::File, io::Write};

use super::ProtocolError;

pub const SECRET_FILE: &str = "./qos.key";

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

pub struct SecretProvisioner {
	shares: Shares,
	pub secret: Option<Secret>,
}

impl SecretProvisioner {
	pub fn new() -> Self {
		Self { shares: Vec::new(), secret: None }
	}

	pub fn add_share(&mut self, share: Share) -> Result<(), ProtocolError> {
		if share.len() == 0 {
			return Err(ProtocolError::InvalidShare)
		}

		self.shares.push(share);
		Ok(())
	}

	pub fn reconstruct(&mut self) -> Result<Secret, ProtocolError> {
		let secret = qos_crypto::shares_reconstruct(&self.shares);

		// TODO: Add better validation...
		if secret.len() == 0 {
			return Err(ProtocolError::ReconstructionError)
		}

		// TODO: Make errors more specific...
		let mut file = File::create(SECRET_FILE)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		file.write_all(&secret)
			.map_err(|_e| ProtocolError::ReconstructionError)?;

		Ok(secret)
	}
}
