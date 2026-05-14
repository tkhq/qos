//! Logic for accessing read only QOS state.

use std::{
	fs,
	os::unix::fs::PermissionsExt,
	path::{Path, PathBuf},
};

use qos_p256::P256Pair;

use crate::OCI_DIR;
use crate::protocol::{
	ProtocolError, msg::WorkloadStatus,
	services::boot::VersionedManifestEnvelope,
};

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

/// Handle for accessing the enclave ephemeral key.
#[derive(Debug, Clone, Copy)]
pub struct EphemeralKeyHandle<S = String> {
	ephemeral_key_path: S,
}

impl<P> EphemeralKeyHandle<P>
where
	P: AsRef<Path>,
{
	/// Create a new instance of [`Self`].
	#[must_use]
	pub fn new(ephemeral_key_path: P) -> Self {
		Self { ephemeral_key_path }
	}

	/// Get the Ephemeral Key Pair
	///
	/// # Errors
	///
	/// Errors if the Ephemeral key pair isn't present or can't be built.
	pub fn get_ephemeral_key(&self) -> Result<P256Pair, ProtocolError> {
		let pair = P256Pair::from_hex_file(&self.ephemeral_key_path)
			.map_err(ProtocolError::FailedToGetEphemeralKey)?;
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
	ephemeral: EphemeralKeyHandle,
	/// Path to the file containing the PEM encoded Quorum Key.
	quorum: QuorumKeyHandle,
	/// Path to the file containing the Borsh encoded [`ManifestEnvelope`].
	manifest: String,
	/// Path to the file containing the pivot.
	pivot: String,
	/// Path to OCI runtime state.
	oci_dir: PathBuf,
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
			ephemeral: EphemeralKeyHandle::new(ephemeral),
			quorum: QuorumKeyHandle::new(quorum),
			manifest,
			pivot,
			oci_dir: PathBuf::from(OCI_DIR),
		}
	}

	/// Create a new instance of [`Self`] with an explicit OCI runtime directory.
	#[must_use]
	pub fn new_with_oci_dir(
		ephemeral: String,
		quorum: String,
		manifest: String,
		pivot: String,
		oci_dir: PathBuf,
	) -> Self {
		Self {
			ephemeral: EphemeralKeyHandle::new(ephemeral),
			quorum: QuorumKeyHandle::new(quorum),
			manifest,
			pivot,
			oci_dir,
		}
	}

	/// Get the Ephemeral Key pair.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral Key isn't present.
	pub fn get_ephemeral_key(&self) -> Result<P256Pair, ProtocolError> {
		self.ephemeral.get_ephemeral_key()
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
			&self.ephemeral.ephemeral_key_path,
			&pair.to_master_seed_hex(),
			ProtocolError::FailedToPutEphemeralKey,
		)
	}

	/// Rotate the ephemeral key to a new key pair. This happens post-boot, to protect key material encrypted to it.
	/// QOS apps can then use this new ephemeral key without worrying about implications for boot flows.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral key isn't present already, or if the delete fails, or if the new write fails.
	pub fn rotate_ephemeral_key(
		&self,
		new_pair: &P256Pair,
	) -> Result<(), ProtocolError> {
		let path = Path::new(&self.ephemeral.ephemeral_key_path);
		if !path.exists() {
			Err(ProtocolError::CannotRotateNonExistentEphemeralKey)?;
		}

		fs::remove_file(path).map_err(|e| {
			ProtocolError::CannotDeleteEphemeralKey(e.to_string())
		})?;

		Self::write_as_read_only(
			path,
			&new_pair.to_master_seed_hex(),
			ProtocolError::FailedToPutEphemeralKey,
		)
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
	) -> Result<VersionedManifestEnvelope, ProtocolError> {
		let contents = fs::read(&self.manifest)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)?;
		let manifest =
			VersionedManifestEnvelope::try_from_slice_compat(&contents)
				.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)?;

		Ok(manifest)
	}

	/// Put the Manifest.
	///
	/// # Errors
	///
	/// Errors if the Manifest has already been put.
	pub fn put_manifest_envelope<E>(
		&self,
		manifest_envelope: E,
	) -> Result<(), ProtocolError>
	where
		E: Into<VersionedManifestEnvelope>,
	{
		let manifest_envelope = manifest_envelope.into();
		Self::write_as_read_only(
			&self.manifest,
			&manifest_envelope
				.to_storage_vec()
				.map_err(|_| ProtocolError::FailedToPutManifestEnvelope)?,
			ProtocolError::FailedToPutManifestEnvelope,
		)
	}

	/// Put the Manifest, overwriting it if it already exists.
	///
	/// **Warning**: This should not be used after pivoting. It is only meant to
	/// be used when updating the manifest envelope while provisioning.
	pub(crate) fn mutate_manifest_envelope<
		F: FnOnce(VersionedManifestEnvelope) -> VersionedManifestEnvelope,
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
		fs::write(
			&self.manifest,
			manifest_envelope
				.to_storage_vec()
				.map_err(|_| ProtocolError::FailedToPutManifestEnvelope)?,
		)
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
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] if the pivot already exists, the
	/// directory cannot be created, or the file cannot be written.
	pub fn put_pivot(&self, pivot: &[u8]) -> Result<(), ProtocolError> {
		if Path::new(&self.pivot).exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		if let Some(parent) = Path::new(&self.pivot).parent()
			&& !parent.exists()
		{
			fs::create_dir_all(parent)
				.map_err(|_| ProtocolError::FailedToPutPivot)?;
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

	/// Return the root directory for OCI runtime state.
	#[must_use]
	pub fn oci_dir(&self) -> PathBuf {
		self.oci_dir.clone()
	}

	/// Return the directory for verified OCI content blobs.
	#[must_use]
	pub fn oci_content_dir(&self) -> PathBuf {
		self.oci_dir().join("content").join("blobs").join("sha256")
	}

	/// Return the path for a verified OCI blob by lowercase SHA-256 hex.
	#[must_use]
	pub fn oci_blob_path(&self, hex: &str) -> PathBuf {
		self.oci_content_dir().join(hex)
	}

	/// Put a verified OCI content blob.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] if the blob cannot be written.
	pub fn put_oci_blob(
		&self,
		hex: &str,
		blob: &[u8],
	) -> Result<(), ProtocolError> {
		let path = self.oci_blob_path(hex);
		if path.exists() {
			return Ok(());
		}
		if let Some(parent) = path.parent()
			&& !parent.exists()
		{
			fs::create_dir_all(parent).map_err(|_| {
				ProtocolError::InvalidOciImage(
					"failed to create OCI content directory".to_string(),
				)
			})?;
		}
		let tmp_path = path.with_extension("tmp");
		fs::write(&tmp_path, blob).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to write OCI blob".to_string(),
			)
		})?;
		fs::rename(&tmp_path, &path).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to commit OCI blob".to_string(),
			)
		})?;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).map_err(
			|_| {
				ProtocolError::InvalidOciImage(
					"failed to make OCI blob read-only".to_string(),
				)
			},
		)?;
		Ok(())
	}

	/// Return true if a verified OCI blob exists.
	#[must_use]
	pub fn oci_blob_exists(&self, hex: &str) -> bool {
		self.oci_blob_path(hex).exists()
	}

	/// Read a verified OCI content blob by lowercase SHA-256 hex.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] when the blob cannot be read.
	pub fn get_oci_blob(&self, hex: &str) -> Result<Vec<u8>, ProtocolError> {
		fs::read(self.oci_blob_path(hex)).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to read OCI blob".to_string(),
			)
		})
	}

	/// Return the directory containing OCI runtime bundles.
	#[must_use]
	pub fn oci_bundles_dir(&self) -> PathBuf {
		self.oci_dir().join("bundles")
	}

	/// Return the rootfs path for an OCI image digest.
	#[must_use]
	pub fn oci_rootfs_dir(&self, manifest_hex: &str) -> PathBuf {
		self.oci_bundles_dir().join(manifest_hex).join("rootfs")
	}

	/// Return the path to the workload status file.
	#[must_use]
	pub fn workload_status_path(&self) -> PathBuf {
		self.oci_dir().join("workload_status.json")
	}

	/// Write workload status, replacing any previous status.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] if the status cannot be serialized or written.
	pub fn put_workload_status(
		&self,
		status: &WorkloadStatus,
	) -> Result<(), ProtocolError> {
		let path = self.workload_status_path();
		if let Some(parent) = path.parent()
			&& !parent.exists()
		{
			fs::create_dir_all(parent).map_err(|_| {
				ProtocolError::InvalidOciImage(
					"failed to create workload status directory".to_string(),
				)
			})?;
		}
		let bytes = serde_json::to_vec(status).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to encode workload status".to_string(),
			)
		})?;
		let tmp_path = path.with_extension("tmp");
		fs::write(&tmp_path, bytes).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to write workload status".to_string(),
			)
		})?;
		fs::rename(&tmp_path, &path).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to commit workload status".to_string(),
			)
		})
	}

	/// Read workload status, if present.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] if the status file is present but invalid.
	pub fn get_workload_status(
		&self,
	) -> Result<Option<WorkloadStatus>, ProtocolError> {
		let path = self.workload_status_path();
		if !path.exists() {
			return Ok(None);
		}
		let bytes = fs::read(path).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to read workload status".to_string(),
			)
		})?;
		serde_json::from_slice(&bytes).map(Some).map_err(|_| {
			ProtocolError::InvalidOciImage(
				"failed to decode workload status".to_string(),
			)
		})
	}

	/// Read the raw ephemeral key file bytes.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] when the file cannot be read.
	pub fn ephemeral_key_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
		fs::read(&self.ephemeral.ephemeral_key_path)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)
	}

	/// Read the raw quorum key file bytes.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] when the file cannot be read.
	pub fn quorum_key_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
		fs::read(&self.quorum.quorum)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)
	}

	/// Read the raw manifest envelope file bytes.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError`] when the file cannot be read.
	pub fn manifest_envelope_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
		fs::read(&self.manifest)
			.map_err(|_| ProtocolError::FailedToGetManifestEnvelope)
	}

	/// Helper function for ready only writes that also ensures full write atomicity by renaming at the end.
	fn write_as_read_only<P: AsRef<Path>>(
		path: P,
		buf: &[u8],
		err: ProtocolError,
	) -> Result<(), ProtocolError> {
		if path.as_ref().exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		if let Some(parent) = path.as_ref().parent()
			&& !parent.exists()
		{
			fs::create_dir_all(parent).map_err(|_| err.clone())?;
		}

		let tmp_path = PathBuf::from(path.as_ref()).with_extension("tmp");

		fs::write(&tmp_path, buf).map_err(|_| err.clone())?;

		// atomically move to destination once fully written to prevent partial reads
		fs::rename(&tmp_path, &path)?;

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
		Manifest, ManifestEnvelope, ManifestSet, Namespace, NitroConfig,
		PatchSet, PivotConfig, RestartPolicy, ShareSet,
	};

	#[test]
	fn put_ephemeral_key_is_read_only_write() {
		let pivot_file =
			PathWrapper::from("put_ephemeral_key_is_read_only_write.pivot");
		let ephemeral_file = PathWrapper::from(
			"put_ephemeral_key_is_read_only_write_eph.secret",
		);
		let quorum_file = PathWrapper::from(
			"put_ephemeral_key_is_read_only_write_quor.secret",
		);
		let manifest_file =
			PathWrapper::from("put_ephemeral_key_is_read_only_write.manifest");

		let handles = Handles::new(
			ephemeral_file.display().to_string(),
			quorum_file.display().to_string(),
			manifest_file.display().to_string(),
			pivot_file.display().to_string(),
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
		let pivot_file =
			PathWrapper::from("put_quorum_key_is_read_only_write.pivot");
		let ephemeral_file =
			PathWrapper::from("put_quorum_key_is_read_only_write_eph.secret");
		let quorum_file =
			PathWrapper::from("put_quorum_key_is_read_only_write_quor.secret");
		let manifest_file =
			PathWrapper::from("put_quorum_key_is_read_only_write.manifest");

		let handles = Handles::new(
			ephemeral_file.display().to_string(),
			quorum_file.display().to_string(),
			manifest_file.display().to_string(),
			pivot_file.display().to_string(),
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
		let pivot_file =
			PathWrapper::from("put_pivot_is_read_only_write.pivot");
		let ephemeral_file =
			PathWrapper::from("put_pivot_is_read_only_write_eph.secret");
		let quorum_file =
			PathWrapper::from("put_pivot_is_read_only_write_quor.secret");

		let manifest_file =
			PathWrapper::from("put_pivot_is_read_only_write.manifest");

		let handles = Handles::new(
			ephemeral_file.display().to_string(),
			quorum_file.display().to_string(),
			manifest_file.display().to_string(),
			pivot_file.display().to_string(),
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
		let pivot_file =
			PathWrapper::from("put_manifest_is_read_only_write.pivot");
		let ephemeral_file =
			PathWrapper::from("put_manifest_is_read_only_write_eph.secret");
		let quorum_file =
			PathWrapper::from("put_manifest_is_read_only_write_quor.secret");
		let manifest_file =
			PathWrapper::from("put_manifest_is_read_only_write.manifest");

		let handles = Handles::new(
			ephemeral_file.display().to_string(),
			quorum_file.display().to_string(),
			manifest_file.display().to_string(),
			pivot_file.display().to_string(),
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
				..Default::default()
			},
			manifest_set: ManifestSet { threshold: 2, members: vec![] },
			share_set: ShareSet { threshold: 2, members: vec![] },
			patch_set: PatchSet::default(),
		};

		let manifest_envelope =
			VersionedManifestEnvelope::V1(ManifestEnvelope {
				manifest,
				manifest_set_approvals: vec![],
				share_set_approvals: vec![],
			});

		let result = handles.put_manifest_envelope(&manifest_envelope);
		let error =
			handles.put_manifest_envelope(&manifest_envelope).unwrap_err();

		assert!(result.is_ok());
		assert_eq!(error, ProtocolError::CannotModifyPostPivotStatic);
		assert!(handles.manifest_envelope_exists());
		assert_eq!(handles.get_manifest_envelope().unwrap(), manifest_envelope);
	}
}
