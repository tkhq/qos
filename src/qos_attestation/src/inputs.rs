//! Expected boot inputs constructed from a public key and manifest in memory.

use std::fmt;

use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_p256::P256Public;

/// What an attestation document must bind to.
#[derive(Clone, PartialEq, Eq)]
pub struct AttestationInputs {
	/// The expected live ephemeral public key for signing and encryption.
	pub ephemeral_public_key: P256Public,
	/// The manifest hash, attested in `user_data`.
	pub manifest_hash: [u8; 32],
	/// Expected PCR0, from the manifest.
	pub pcr0: Vec<u8>,
	/// Expected PCR1, from the manifest.
	pub pcr1: Vec<u8>,
	/// Expected PCR2, from the manifest.
	pub pcr2: Vec<u8>,
	/// Expected PCR3, from the manifest.
	pub pcr3: Vec<u8>,
}

impl fmt::Debug for AttestationInputs {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("AttestationInputs")
			.field(
				"ephemeral_public_key",
				&self.ephemeral_public_key.to_bytes(),
			)
			.field("manifest_hash", &self.manifest_hash)
			.field("pcr0", &self.pcr0)
			.field("pcr1", &self.pcr1)
			.field("pcr2", &self.pcr2)
			.field("pcr3", &self.pcr3)
			.finish()
	}
}

impl AttestationInputs {
	/// Build inputs from an ephemeral public key and a manifest envelope.
	/// Supports v0, v1 and v2 manifests.
	#[must_use]
	pub fn new(
		ephemeral_public_key: P256Public,
		envelope: &VersionedManifestEnvelope,
	) -> Self {
		let enclave = envelope.enclave();
		Self {
			ephemeral_public_key,
			manifest_hash: envelope.manifest_hash(),
			pcr0: enclave.pcr0.clone(),
			pcr1: enclave.pcr1.clone(),
			pcr2: enclave.pcr2.clone(),
			pcr3: enclave.pcr3.clone(),
		}
	}
}
