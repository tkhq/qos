use std::{fs::File, io::Write};

use super::ProtocolError;

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

/// Shamir Secret provisioner.
pub struct SecretProvisioner {
	shares: Shares,
	// TODO: maybe don't store secret and just return it on reconstruct
	secret: Option<Secret>,
	secret_file: String,
}

impl SecretProvisioner {
	/// Create a instance of [`Self`].
	pub fn new(secret_file: String) -> Self {
		Self { shares: Vec::new(), secret: None, secret_file }
	}

	/// Add a share to later be used to reconstruct.
	pub fn add_share(&mut self, share: Share) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}

		self.shares.push(share);
		Ok(())
	}

	/// Attempt to reconstruct the secret from the
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

		self.secret = Some(secret.clone());
		Ok(secret)
	}
}
