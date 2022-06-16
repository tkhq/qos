use qos_crypto::RsaPair;

use crate::protocol::{ProtocolError, ProtocolPhase, ProtocolState};

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

/// Shamir Secret provisioner.
pub struct SecretBuilder {
	shares: Shares,
}

impl SecretBuilder {
	/// Create a instance of [`Self`].
	pub fn new() -> Self {
		Self { shares: Vec::new() }
	}

	/// Add a share to later be used to reconstruct.
	pub(crate) fn add_share(
		&mut self,
		share: Share,
	) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}

		self.shares.push(share);
		Ok(())
	}

	/// Attempt to reconstruct the secret from the
	pub fn build(&self) -> Result<Secret, ProtocolError> {
		let secret = qos_crypto::shares_reconstruct(&self.shares);

		// TODO: Add better validation...
		if secret.is_empty() {
			return Err(ProtocolError::ReconstructionError);
		}

		Ok(secret)
	}

	/// The count of shares.
	pub(crate) fn count(&self) -> usize {
		self.shares.len()
	}
}

pub(in crate::protocol) fn provision(
	encrypted_share: &[u8],
	state: &mut ProtocolState,
) -> Result<bool, ProtocolError> {
	let ephemeral_key = RsaPair::from_pem_file(&state.ephemeral_key_file)?;
	let share = ephemeral_key.envelope_decrypt(encrypted_share)?;

	state.provisioner.add_share(share)?;

	let quorum_threshold =
		state.manifest.as_ref().unwrap().manifest.quorum_set.threshold as usize;
	if state.provisioner.count() < quorum_threshold {
		// Nothing else to do if we don't have the threshold to reconstruct
		return Ok(false);
	}

	let private_key_der = state.provisioner.build()?;
	let public_key_der =
		qos_crypto::RsaPair::from_der(&private_key_der)?.public_key_to_der()?;

	if public_key_der != state.manifest.as_ref().unwrap().manifest.quorum_key {
		// We did not construct the intended key
		return Err(ProtocolError::ReconstructionError);
	}

	std::fs::write(&state.secret_file, private_key_der)?;
	state.phase = ProtocolPhase::QuorumKeyProvisioned;
	Ok(true)
}

// TODO: Basic unit tests
// TODO: put service here
