use super::ProtocolError;

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

/// Shamir Secret provisioner.
pub struct SecretProvisioner {
	shares: Shares,
	secret_file: String,
}

impl SecretProvisioner {
	/// Create a instance of [`Self`].
	pub fn new(secret_file: String) -> Self {
		Self { shares: Vec::new(), secret_file }
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

		Ok(secret)
	}

	/// The count of shares.
	pub fn count(&self) -> usize {
		self.shares.len()
	}

	/// Path to the secrete file
	pub fn secret_file(&self) -> &str {
		&self.secret_file
	}
}

// TODO: Basic unit tests
// TODO: put service here
