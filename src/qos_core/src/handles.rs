//! Logic for accessing read only QOS state.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use borsh::{BorshDeserialize, BorshSerialize};
use qos_p256::P256Pair;

use crate::protocol::{services::boot::ManifestEnvelope, ProtocolError};

/// Handle for accessing the quorum key.
#[derive(Debug, Clone)]
pub struct QuorumKeyHandle {
	quorum: String,
}

impl QuorumKeyHandle {
	/// Create a new instance of [`Self`].
	#[must_use]
	pub fn new(quorum: String) -> Self {
		Self { quorum }
	}

	/// Get the Quorum Key pair.
	///
	/// # Errors
	///
	/// Errors if the Quorum Key has not been put.
	pub fn get_quorum_key(&self) -> Result<P256Pair, ProtocolError> {
		let pair = P256Pair::from_hex_file(&self.quorum)
			.map_err(ProtocolError::FailedToGetQuorumKey)?;
		Ok(pair)
	}
}

/// Handles for read only state accessible to all of QOS.
///
/// All data here should be "put" once at some point in the boot flow. Once
/// "put", it can only be read.
#[derive(Debug, Clone)]
pub struct Handles {
	/// Path to the file containing the PEM encoded Ephemeral Key.
	ephemeral: String,
	/// Path to the file containing the PEM encoded Quorum Key.
	quorum: QuorumKeyHandle,
	/// Path to the file containing the Borsh encoded [`ManifestEnvelope`].
	manifest: String,
	/// Path to the file containing the pivot.
	pivot: String,
}

impl Handles {
	/// Create a new instance of [`Self`].
	#[must_use]
	pub fn new(
		ephemeral: String,
		quorum: String,
		manifest: String,
		pivot: String,
	) -> Self {
		Self {
			ephemeral,
			quorum: QuorumKeyHandle::new(quorum),
			manifest,
			pivot,
		}
	}

	/// Get the path to the Ephemeral Key.
	#[must_use]
	pub fn ephemeral_key_path(&self) -> String {
		self.ephemeral.clone()
	}

	/// Get the Ephemeral Key pair.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral Key has not been put.
	pub fn get_ephemeral_key(&self) -> Result<P256Pair, ProtocolError> {
		let pair = P256Pair::from_hex_file(&self.ephemeral)
			.map_err(ProtocolError::FailedToGetEphemeralKey)?;
		Ok(pair)
	}

	/// Put the Ephemeral Key pair.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral Key has already been put.
	pub fn put_ephemeral_key(
		&self,
		pair: &P256Pair,
	) -> Result<(), ProtocolError> {
		Self::write_as_read_only(
			&self.ephemeral,
			&pair.to_master_seed_hex(),
			ProtocolError::FailedToPutEphemeralKey,
		)
	}

	/// Delete the Ephemeral Key. Silently fails if the Ephemeral Key does not
	/// exist.
	pub fn delete_ephemeral_key(&self) {
		drop(fs::remove_file(&self.ephemeral));
	}

	/// Get the Quorum Key pair.
	///
	/// # Errors
	///
	/// Errors if the Quorum Key has not been put.
	pub fn get_quorum_key(&self) -> Result<P256Pair, ProtocolError> {
		self.quorum.get_quorum_key()
	}

	/// Put the Quorum Key pair.
	///
	/// # Errors
	///
	/// Errors if the Quorum Key has already been put.
	pub fn put_quorum_key(&self, pair: &P256Pair) -> Result<(), ProtocolError> {
		Self::write_as_read_only(
			&self.quorum.quorum,
			&pair.to_master_seed_hex(),
			ProtocolError::FailedToPutQuorumKey,
		)
	}

	/// Returns true if the Quorum Key file exists.
	#[must_use]
	pub fn quorum_key_exists(&self) -> bool {
		Path::new(&self.quorum.quorum).exists()
	}

	/// Get the Manifest.
	///
	/// # Errors
	///
	/// Errors if the Manifest has not been put.
	pub fn get_manifest_envelope(
		&self,
	) -> Result<ManifestEnvelope, ProtocolError> {
		let contents = fs::read(&self.manifest)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)?;
		let manifest = ManifestEnvelope::try_from_slice(&contents)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)?;
		Ok(manifest)
	}

	/// Put the Manifest.
	///
	/// # Errors
	///
	/// Errors if the Manifest has already been put.
	pub fn put_manifest_envelope(
		&self,
		manifest_envelope: &ManifestEnvelope,
	) -> Result<(), ProtocolError> {
		Self::write_as_read_only(
			&self.manifest,
			&manifest_envelope.try_to_vec()?,
			ProtocolError::FailedToPutManifestEnvelope,
		)
	}

	/// Put the Manifest, overwriting it if it already exists.
	///
	/// **Warning**: This should not be used after pivoting. It is only meant to
	/// be used when updating the manifest envelope while provisioning.
	pub(crate) fn mutate_manifest_envelope<
		F: FnOnce(ManifestEnvelope) -> ManifestEnvelope,
	>(
		&self,
		mutate: F,
	) -> Result<(), ProtocolError> {
		let manifest_envelope = self.get_manifest_envelope()?;

		let manifest_envelope = mutate(manifest_envelope);

		// Temporarily set permissions so we can write the manifest envelope
		fs::set_permissions(
			&self.manifest,
			std::fs::Permissions::from_mode(0o666),
		)?;
		fs::write(&self.manifest, manifest_envelope.try_to_vec()?)
			.map_err(|_| ProtocolError::FailedToPutManifestEnvelope)?;

		// Set the permissions back to read only
		fs::set_permissions(
			&self.manifest,
			std::fs::Permissions::from_mode(0o444),
		)?;

		Ok(())
	}

	/// Returns true if the Manifest file exists.
	#[must_use]
	pub fn manifest_envelope_exists(&self) -> bool {
		Path::new(&self.manifest).exists()
	}

	/// Get the path to the Pivot binary.
	#[must_use]
	pub fn pivot_path(&self) -> String {
		self.pivot.clone()
	}

	/// Put the Pivot binary, ensuring it is an executable.
	pub fn put_pivot(&self, pivot: &[u8]) -> Result<(), ProtocolError> {
		if Path::new(&self.pivot).exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		if let Some(parent) = Path::new(&self.pivot).parent() {
			if !parent.exists() {
				fs::create_dir_all(parent)
					.map_err(|_| ProtocolError::FailedToPutPivot)?;
			}
		}

		fs::write(&self.pivot, pivot)
			.map_err(|_| ProtocolError::FailedToPutPivot)?;
		fs::set_permissions(
			&self.pivot,
			std::fs::Permissions::from_mode(0o111),
		)
		.map_err(|_| ProtocolError::FailedToPutPivot)?;
		Ok(())
	}

	/// Returns true if the Pivot file exists.
	#[must_use]
	pub fn pivot_exists(&self) -> bool {
		Path::new(&self.pivot).exists()
	}

	/// Helper function for ready only writes.
	fn write_as_read_only<P: AsRef<Path>>(
		path: P,
		buf: &[u8],
		err: ProtocolError,
	) -> Result<(), ProtocolError> {
		if path.as_ref().exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		if let Some(parent) = path.as_ref().parent() {
			if !parent.exists() {
				fs::create_dir_all(parent).map_err(|_| err.clone())?;
			}
		}

		fs::write(&path, buf).map_err(|_| err.clone())?;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
			.map_err(|_| err)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {

	use qos_crypto::sha_256;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::protocol::services::boot::{
		Manifest, ManifestSet, Namespace, NitroConfig, PatchSet, PivotConfig,
		RestartPolicy, ShareSet,
	};

	#[test]
	fn put_ephemeral_key_is_read_only_write() {
		let pivot_file: PathWrapper =
			"put_ephemeral_key_is_read_only_write.pivot".into();
		let ephemeral_file: PathWrapper =
			"put_ephemeral_key_is_read_only_write_eph.secret".into();
		let quorum_file: PathWrapper =
			"put_ephemeral_key_is_read_only_write_quor.secret".into();
		let manifest_file: PathWrapper =
			"put_ephemeral_key_is_read_only_write.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			(*quorum_file).to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);

		let ephemeral_key = P256Pair::generate().unwrap();
		let result = handles.put_ephemeral_key(&ephemeral_key);
		let error = handles.put_ephemeral_key(&ephemeral_key).unwrap_err();

		assert!(result.is_ok());
		assert_eq!(error, ProtocolError::CannotModifyPostPivotStatic);
		assert!(handles.get_ephemeral_key().unwrap() == ephemeral_key);
	}

	#[test]
	fn put_quorum_key_is_read_only_write() {
		let pivot_file: PathWrapper =
			"put_quorum_key_is_read_only_write.pivot".into();
		let ephemeral_file: PathWrapper =
			"put_quorum_key_is_read_only_write_eph.secret".into();
		let quorum_file: PathWrapper =
			"put_pivot_is_read_only_write_quor.secret".into();
		let manifest_file: PathWrapper =
			"put_quorum_key_is_read_only_write.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			(*quorum_file).to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);

		let quorum_key = P256Pair::generate().unwrap();
		let result = handles.put_quorum_key(&quorum_key);
		let error = handles.put_quorum_key(&quorum_key).unwrap_err();

		assert!(result.is_ok());
		assert_eq!(error, ProtocolError::CannotModifyPostPivotStatic);
		assert!(handles.quorum_key_exists());
		assert!(handles.get_quorum_key().unwrap() == quorum_key);
	}

	#[test]
	fn put_pivot_is_read_only_write() {
		let pivot_file: PathWrapper =
			"put_pivot_is_read_only_write.pivot".into();
		let ephemeral_file: PathWrapper =
			"put_pivot_is_read_only_write_eph.secret".into();
		let quorum_file: PathWrapper =
			"put_pivot_is_read_only_write_quor.secret".into();

		let manifest_file: PathWrapper =
			"put_pivot_is_read_only_write.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			(*quorum_file).to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);

		let pivot = b"this is a pivot binary".to_vec();
		let result = handles.put_pivot(&pivot);
		let error = handles.put_pivot(&pivot).unwrap_err();

		assert!(result.is_ok());
		assert_eq!(error, ProtocolError::CannotModifyPostPivotStatic);
		assert!(handles.pivot_exists());
	}

	#[test]
	fn put_manifest_is_read_only_write() {
		let pivot_file: PathWrapper =
			"put_manifest_is_read_only_write.pivot".into();
		let ephemeral_file: PathWrapper =
			"put_manifest_is_read_only_write_eph.secret".into();
		let quorum_file: PathWrapper =
			"put_manifest_is_read_only_write_quor.secret".into();
		let manifest_file: PathWrapper =
			"put_manifest_is_read_only_write.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			(*quorum_file).to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);

		let pivot = b"this is a pivot binary".to_vec();

		let manifest = Manifest {
			namespace: Namespace {
				nonce: 420,
				name: "vape lord".to_string(),
				quorum_key: P256Pair::generate()
					.unwrap()
					.public_key()
					.to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			},
			pivot: PivotConfig {
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
			},
			manifest_set: ManifestSet { threshold: 2, members: vec![] },
			share_set: ShareSet { threshold: 2, members: vec![] },
			patch_set: PatchSet::default(),
		};

		let manifest_envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};

		let result = handles.put_manifest_envelope(&manifest_envelope);
		let error =
			handles.put_manifest_envelope(&manifest_envelope).unwrap_err();

		assert!(result.is_ok());
		assert_eq!(error, ProtocolError::CannotModifyPostPivotStatic);
		assert!(handles.manifest_envelope_exists());
		assert!(handles.get_manifest_envelope().unwrap() == manifest_envelope);
	}
}
