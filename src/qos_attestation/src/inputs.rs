//! The inputs a pivot attests: its ephemeral key and its manifest.

use std::{fs::File, io::Read, path::Path};

use qos_core::{
	handles::EphemeralKeyHandle,
	protocol::services::boot::{NitroConfig, VersionedManifestEnvelope},
};

use crate::Error;

/// Largest manifest file [`AttestationInputs::load`] will read.
pub const MAX_MANIFEST_BYTES: u64 = 10 * 1024 * 1024;

/// What an attestation document must bind to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationInputs {
	/// The ephemeral public key, as `P256Pair::public_key().to_bytes()`.
	pub ephemeral_public_key: Vec<u8>,
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

impl AttestationInputs {
	/// Build inputs from an ephemeral public key and a manifest envelope.
	///
	/// # Errors
	///
	/// Returns [`Error::UnsupportedManifestVersion`] for v0 manifests.
	pub fn new(
		ephemeral_public_key: Vec<u8>,
		envelope: &VersionedManifestEnvelope,
	) -> Result<Self, Error> {
		let enclave: &NitroConfig = match envelope {
			VersionedManifestEnvelope::V2(e) => &e.manifest.enclave,
			VersionedManifestEnvelope::V1(e) => &e.manifest.enclave,
			// No boot-proof encoding exists for v0, so never attest it.
			VersionedManifestEnvelope::V0(_) => {
				return Err(Error::UnsupportedManifestVersion("v0"));
			}
		};
		Ok(Self {
			ephemeral_public_key,
			manifest_hash: envelope.manifest_hash(),
			pcr0: enclave.pcr0.clone(),
			pcr1: enclave.pcr1.clone(),
			pcr2: enclave.pcr2.clone(),
			pcr3: enclave.pcr3.clone(),
		})
	}

	/// Load inputs from an ephemeral key file and a manifest file.
	///
	/// A pivot only ever sees the live ephemeral key: QOS rotates to it
	/// before writing the quorum key, which is what starts the pivot.
	///
	/// # Errors
	///
	/// Returns an error if either file can't be read or decoded, if the
	/// manifest is larger than [`MAX_MANIFEST_BYTES`], or if it is v0.
	pub fn load(
		ephemeral_key_path: &Path,
		manifest_path: &Path,
	) -> Result<(Self, VersionedManifestEnvelope), Error> {
		let envelope = read_manifest_envelope(manifest_path)?;
		let key = EphemeralKeyHandle::new(ephemeral_key_path)
			.get_ephemeral_key()
			.map_err(|e| Error::EphemeralKey(format!("{e:?}")))?;
		let inputs = Self::new(key.public_key().to_bytes(), &envelope)?;
		Ok((inputs, envelope))
	}

	/// [`Self::load`] from the paths QOS writes inside the enclave.
	///
	/// # Errors
	///
	/// See [`Self::load`].
	pub fn load_default() -> Result<(Self, VersionedManifestEnvelope), Error> {
		Self::load(
			Path::new(qos_core::EPHEMERAL_KEY_FILE),
			Path::new(qos_core::MANIFEST_FILE),
		)
	}
}

/// Read and decode a manifest envelope, refusing files larger than
/// [`MAX_MANIFEST_BYTES`].
///
/// # Errors
///
/// Returns an error if the file can't be read, is too large, or doesn't
/// decode.
pub fn read_manifest_envelope(
	path: &Path,
) -> Result<VersionedManifestEnvelope, Error> {
	let file = File::open(path).map_err(Error::ManifestRead)?;
	let mut bytes = Vec::new();
	// Read one byte past the limit so an oversized file is detected.
	file.take(MAX_MANIFEST_BYTES + 1)
		.read_to_end(&mut bytes)
		.map_err(Error::ManifestRead)?;
	if bytes.len() as u64 > MAX_MANIFEST_BYTES {
		return Err(Error::ManifestTooLarge { limit: MAX_MANIFEST_BYTES });
	}
	VersionedManifestEnvelope::try_from_slice_compat(&bytes)
		.map_err(|e| Error::ManifestDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
	use qos_p256::P256Pair;

	use super::*;
	use crate::test_support::{
		TempDir, v0_envelope, v1_envelope, v2_envelope, write_key,
		write_manifest,
	};

	#[test]
	fn load_reads_key_and_v2_manifest() {
		let dir = TempDir::new("load_v2");
		let pair = P256Pair::generate().unwrap();
		let envelope = v2_envelope();
		let key_path = write_key(&dir, &pair);
		let manifest_path = write_manifest(&dir, &envelope);

		let (inputs, loaded) =
			AttestationInputs::load(&key_path, &manifest_path).unwrap();

		assert_eq!(loaded, envelope);
		assert_eq!(inputs.ephemeral_public_key, pair.public_key().to_bytes());
		assert_eq!(inputs.manifest_hash, envelope.manifest_hash());
		let VersionedManifestEnvelope::V2(e) = &envelope else {
			unreachable!()
		};
		assert_eq!(inputs.pcr0, e.manifest.enclave.pcr0);
		assert_eq!(inputs.pcr3, e.manifest.enclave.pcr3);
	}

	#[test]
	fn load_accepts_v1() {
		let dir = TempDir::new("load_v1");
		let pair = P256Pair::generate().unwrap();
		let envelope = v1_envelope();
		let (inputs, _) = AttestationInputs::load(
			&write_key(&dir, &pair),
			&write_manifest(&dir, &envelope),
		)
		.unwrap();
		assert_eq!(inputs.manifest_hash, envelope.manifest_hash());
	}

	#[test]
	fn load_rejects_v0() {
		let dir = TempDir::new("load_v0");
		let pair = P256Pair::generate().unwrap();
		let err = AttestationInputs::load(
			&write_key(&dir, &pair),
			&write_manifest(&dir, &v0_envelope()),
		)
		.unwrap_err();
		assert!(matches!(err, Error::UnsupportedManifestVersion("v0")));
	}

	#[test]
	fn read_rejects_manifest_over_the_limit() {
		let dir = TempDir::new("too_large");
		let path = dir.path().join("manifest");
		let limit = usize::try_from(MAX_MANIFEST_BYTES).unwrap();
		std::fs::write(&path, vec![b' '; limit + 1]).unwrap();

		let err = read_manifest_envelope(&path).unwrap_err();
		assert!(matches!(err, Error::ManifestTooLarge { .. }));
	}

	#[test]
	fn read_reports_missing_and_garbage_files() {
		let dir = TempDir::new("missing");
		let path = dir.path().join("manifest");
		assert!(matches!(
			read_manifest_envelope(&path),
			Err(Error::ManifestRead(_))
		));

		std::fs::write(&path, b"not a manifest").unwrap();
		assert!(matches!(
			read_manifest_envelope(&path),
			Err(Error::ManifestDecode(_))
		));
	}

	#[test]
	fn load_reports_missing_key() {
		let dir = TempDir::new("no_key");
		let manifest_path = write_manifest(&dir, &v2_envelope());
		let err = AttestationInputs::load(
			&dir.path().join("missing.key"),
			&manifest_path,
		)
		.unwrap_err();
		assert!(matches!(err, Error::EphemeralKey(_)));
	}
}
