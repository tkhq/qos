//! OCI image archive verification and import.

use std::{
	collections::{BTreeSet, HashMap},
	fs,
	io::{Cursor, Read},
	os::unix::fs::{PermissionsExt, symlink},
	path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use oci_spec::image::{
	Descriptor, ImageConfiguration, ImageManifest, MediaType,
};
use oci_spec::runtime::{
	LinuxNamespaceType, MountBuilder, Process, RootBuilder, Spec, User,
};

use crate::{
	handles::Handles,
	protocol::{
		ProtocolError,
		services::boot::{OciDigest, PivotOciImageConfigV2},
	},
};

const OCI_LAYOUT_FILE: &str = "oci-layout";
const OCI_INDEX_FILE: &str = "index.json";
const QOS_COMPAT_PATHS: &[&str] =
	&["/qos.quorum.key", "/qos.ephemeral.key", "/qos.manifest"];

/// Verified OCI image metadata needed by later launch phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciImage {
	/// Approved image manifest digest.
	pub digest: OciDigest,
	/// Verified image config blob digest.
	pub config_digest: OciDigest,
	/// Verified layer blob digests in application order.
	pub layers: Vec<VerifiedLayer>,
	/// Uncompressed layer diff IDs from the verified image config.
	pub diff_ids: Vec<String>,
	/// Process entrypoint from image config.
	pub entrypoint: Vec<String>,
	/// Process cmd from image config.
	pub cmd: Vec<String>,
	/// Environment entries from image config.
	pub env: Vec<String>,
	/// Working directory from image config.
	pub working_dir: String,
	/// User requested by the image config.
	pub user: String,
	/// Verified volume mount targets from image config.
	pub volumes: Vec<String>,
	/// Verified exposed ports from image config.
	pub exposed_ports: Vec<String>,
}

/// Verified layer metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLayer {
	/// Layer blob digest.
	pub digest: OciDigest,
	/// Whether the layer blob is gzip compressed.
	pub gzip: bool,
}

/// Runtime bundle prepared from a verified OCI image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRuntimeBundle {
	/// OCI bundle directory containing `config.json` and `rootfs`.
	pub bundle_dir: PathBuf,
	/// Root filesystem directory.
	pub rootfs: PathBuf,
	/// Process argv.
	pub argv: Vec<String>,
	/// Process environment.
	pub env: Vec<(String, String)>,
	/// Process working directory inside rootfs.
	pub cwd: String,
	/// Full OCI runtime spec consumed by `libcontainer`.
	pub spec: Spec,
}

/// Verify a protocol-supplied OCI image-layout archive and import reachable
/// blobs into QOS's content store.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the archive, descriptor graph, or image config
/// is outside QOS's supported OCI subset.
pub fn import_oci_layout_archive(
	handles: &Handles,
	pivot: &PivotOciImageConfigV2,
	archive_bytes: &[u8],
) -> Result<VerifiedOciImage, ProtocolError> {
	if archive_bytes.is_empty() {
		return Err(invalid("empty OCI layout archive"));
	}
	if archive_bytes.len() as u64 > pivot.limits.max_compressed_bytes {
		return Err(invalid(
			"OCI layout archive exceeds compressed byte limit",
		));
	}
	if pivot.r#type != super::PivotKind::OciImage {
		return Err(ProtocolError::InvalidPivotMode);
	}
	if !pivot.platform.is_supported() {
		return Err(invalid("unsupported manifest OCI platform"));
	}

	let archive =
		read_layout_archive(archive_bytes, pivot.limits.max_compressed_bytes)?;
	let verified = verify_descriptor_graph(&archive.blobs, pivot)?;

	for hex in verified.reachable_blob_hexes() {
		let blob = archive.blobs.get(&hex).ok_or_else(|| {
			invalid("reachable blob missing after verification")
		})?;
		handles.put_oci_blob(&hex, blob)?;
	}

	Ok(verified)
}

/// Verify stored OCI content, apply layers into a runtime rootfs, and derive the
/// process configuration.
///
/// # Errors
///
/// Returns [`ProtocolError`] when stored content is missing, invalid, or cannot
/// be materialized.
pub fn prepare_oci_runtime_bundle(
	handles: &Handles,
	pivot: &PivotOciImageConfigV2,
) -> Result<OciRuntimeBundle, ProtocolError> {
	let (verified, blobs) =
		inspect_stored_oci_image_with_blobs(handles, pivot)?;
	let rootfs = handles.oci_rootfs_dir(pivot.digest.hex());
	if rootfs.exists() {
		fs::remove_dir_all(&rootfs)
			.map_err(|_| invalid("failed to reset OCI rootfs"))?;
	}
	fs::create_dir_all(&rootfs)
		.map_err(|_| invalid("failed to create OCI rootfs"))?;

	let mut unpacked_bytes = 0_u64;
	let mut entries = 0_u64;
	for (index, layer) in verified.layers.iter().enumerate() {
		let blob = blobs
			.get(layer.digest.hex())
			.ok_or_else(|| invalid("verified layer blob missing"))?;
		let uncompressed = uncompress_layer(blob, layer.gzip)?;
		let actual_diff_id = format!(
			"sha256:{}",
			qos_hex::encode(&qos_crypto::sha_256(&uncompressed))
		);
		if actual_diff_id != verified.diff_ids[index] {
			return Err(invalid("OCI layer diff_id mismatch"));
		}
		apply_layer(
			&rootfs,
			&uncompressed,
			pivot.limits.max_unpacked_bytes,
			pivot.limits.max_entries,
			&mut unpacked_bytes,
			&mut entries,
		)?;
	}

	create_runtime_mount_points(&rootfs, &verified)?;
	materialize_qos_files(handles, &rootfs)?;

	let argv = derive_argv(pivot, &verified)?;
	let env = derive_env(pivot, &verified)?;
	let cwd = derive_cwd(pivot, &verified)?;
	let bundle_dir = rootfs
		.parent()
		.ok_or_else(|| invalid("OCI rootfs has no bundle directory"))?
		.to_path_buf();
	let spec =
		build_runtime_spec(pivot, &verified, &rootfs, &argv, &env, &cwd)?;
	spec.save(bundle_dir.join("config.json"))
		.map_err(|_| invalid("failed to write OCI runtime config"))?;
	Ok(OciRuntimeBundle { bundle_dir, rootfs, argv, env, cwd, spec })
}

/// Verify stored OCI content and return image metadata without unpacking it.
///
/// # Errors
///
/// Returns [`ProtocolError`] when stored content is missing or invalid.
pub fn inspect_stored_oci_image(
	handles: &Handles,
	pivot: &PivotOciImageConfigV2,
) -> Result<VerifiedOciImage, ProtocolError> {
	inspect_stored_oci_image_with_blobs(handles, pivot)
		.map(|(verified, _)| verified)
}

fn inspect_stored_oci_image_with_blobs(
	handles: &Handles,
	pivot: &PivotOciImageConfigV2,
) -> Result<(VerifiedOciImage, HashMap<String, Vec<u8>>), ProtocolError> {
	let manifest_bytes = handles.get_oci_blob(pivot.digest.hex())?;
	let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
		.map_err(|_| invalid("stored OCI manifest is invalid"))?;

	let config_digest = oci_digest_from_descriptor(manifest.config())?;
	let mut blobs = HashMap::new();
	blobs.insert(pivot.digest.hex().to_string(), manifest_bytes);
	blobs.insert(
		config_digest.hex().to_string(),
		handles.get_oci_blob(config_digest.hex())?,
	);
	for layer in manifest.layers() {
		let digest = oci_digest_from_descriptor(layer)?;
		blobs.insert(
			digest.hex().to_string(),
			handles.get_oci_blob(digest.hex())?,
		);
	}

	let verified = verify_descriptor_graph(&blobs, pivot)?;
	Ok((verified, blobs))
}

impl VerifiedOciImage {
	fn reachable_blob_hexes(&self) -> Vec<String> {
		let mut hexes = Vec::with_capacity(self.layers.len() + 2);
		hexes.push(self.digest.hex().to_string());
		hexes.push(self.config_digest.hex().to_string());
		for layer in &self.layers {
			hexes.push(layer.digest.hex().to_string());
		}
		hexes
	}
}

#[derive(Debug)]
struct LayoutArchive {
	blobs: HashMap<String, Vec<u8>>,
}

fn read_layout_archive(
	archive_bytes: &[u8],
	max_imported_bytes: u64,
) -> Result<LayoutArchive, ProtocolError> {
	let cursor = Cursor::new(archive_bytes);
	let mut archive = tar::Archive::new(cursor);
	let mut has_layout = false;
	let mut has_index = false;
	let mut imported_bytes = 0_u64;
	let mut blobs = HashMap::new();

	let entries = archive
		.entries()
		.map_err(|_| invalid("failed to read OCI layout archive"))?;
	for entry in entries {
		let mut entry =
			entry.map_err(|_| invalid("failed to read OCI layout entry"))?;
		reject_unsupported_pax(&mut entry)?;
		let path = entry
			.path()
			.map_err(|_| invalid("invalid OCI layout entry path"))?
			.into_owned();
		validate_archive_path(&path)?;

		let entry_type = entry.header().entry_type();
		if entry_type.is_dir() {
			continue;
		}
		if !entry_type.is_file() {
			return Err(invalid(
				"OCI layout archive contains unsupported entry",
			));
		}
		let mode = entry
			.header()
			.mode()
			.map_err(|_| invalid("invalid OCI layout entry mode"))?;
		if mode & 0o6000 != 0 {
			return Err(invalid("OCI layout entry has setuid/setgid bits"));
		}

		let normalized = path_to_string(&path)?;
		if normalized == OCI_LAYOUT_FILE {
			has_layout = true;
			continue;
		}
		if normalized == OCI_INDEX_FILE {
			has_index = true;
			continue;
		}

		let Some(hex) = normalized.strip_prefix("blobs/sha256/") else {
			return Err(invalid("OCI layout file is outside supported paths"));
		};
		validate_sha256_hex(hex)?;

		let mut blob = Vec::new();
		entry
			.read_to_end(&mut blob)
			.map_err(|_| invalid("failed to read OCI blob"))?;
		imported_bytes = imported_bytes
			.checked_add(blob.len() as u64)
			.ok_or_else(|| invalid("OCI imported byte count overflow"))?;
		if imported_bytes > max_imported_bytes {
			return Err(invalid("OCI imported bytes exceed limit"));
		}
		blobs.insert(hex.to_string(), blob);
	}

	if !has_layout {
		return Err(invalid("OCI layout archive missing oci-layout"));
	}
	if !has_index {
		return Err(invalid("OCI layout archive missing index.json"));
	}

	Ok(LayoutArchive { blobs })
}

fn uncompress_layer(blob: &[u8], gzip: bool) -> Result<Vec<u8>, ProtocolError> {
	if !gzip {
		return Ok(blob.to_vec());
	}
	let mut decoder = GzDecoder::new(blob);
	let mut out = Vec::new();
	decoder
		.read_to_end(&mut out)
		.map_err(|_| invalid("failed to decompress OCI gzip layer"))?;
	Ok(out)
}

#[allow(clippy::too_many_lines)]
fn apply_layer(
	rootfs: &Path,
	layer: &[u8],
	max_unpacked_bytes: u64,
	max_entries: u64,
	unpacked_bytes: &mut u64,
	entries: &mut u64,
) -> Result<(), ProtocolError> {
	let mut archive = tar::Archive::new(Cursor::new(layer));
	let archive_entries = archive
		.entries()
		.map_err(|_| invalid("failed to read OCI layer tar"))?;
	for entry in archive_entries {
		let mut entry =
			entry.map_err(|_| invalid("failed to read OCI layer entry"))?;
		reject_unsupported_pax(&mut entry)?;
		let path = entry
			.path()
			.map_err(|_| invalid("invalid OCI layer entry path"))?
			.into_owned();
		validate_archive_path(&path)?;
		let normalized = path_to_string(&path)?;
		if handle_whiteout(rootfs, &normalized)? {
			continue;
		}
		*entries = entries
			.checked_add(1)
			.ok_or_else(|| invalid("OCI entry count overflow"))?;
		if *entries > max_entries {
			return Err(invalid("OCI layer entry limit exceeded"));
		}

		let mode = entry
			.header()
			.mode()
			.map_err(|_| invalid("invalid OCI layer entry mode"))?;
		let uid = u32::try_from(
			entry
				.header()
				.uid()
				.map_err(|_| invalid("invalid OCI layer entry uid"))?,
		)
		.map_err(|_| invalid("OCI layer entry uid is out of range"))?;
		let gid = u32::try_from(
			entry
				.header()
				.gid()
				.map_err(|_| invalid("invalid OCI layer entry gid"))?,
		)
		.map_err(|_| invalid("OCI layer entry gid is out of range"))?;
		if mode & 0o6000 != 0 {
			return Err(invalid("OCI layer entry has setuid/setgid bits"));
		}

		let target = rootfs.join(&normalized);
		ensure_parent_inside_rootfs(rootfs, &target)?;
		let entry_type = entry.header().entry_type();
		if entry_type.is_gnu_sparse() {
			return Err(invalid("OCI layer sparse files are unsupported"));
		}
		if entry_type.is_dir() {
			fs::create_dir_all(&target)
				.map_err(|_| invalid("failed to create OCI directory"))?;
			fs::set_permissions(
				&target,
				fs::Permissions::from_mode(mode & 0o777),
			)
			.map_err(|_| invalid("failed to set OCI directory mode"))?;
			set_oci_ownership(&target, uid, gid)?;
		} else if entry_type.is_file() {
			if let Some(parent) = target.parent() {
				fs::create_dir_all(parent)
					.map_err(|_| invalid("failed to create OCI file parent"))?;
			}
			let mut data = Vec::new();
			entry
				.read_to_end(&mut data)
				.map_err(|_| invalid("failed to read OCI file entry"))?;
			*unpacked_bytes = unpacked_bytes
				.checked_add(data.len() as u64)
				.ok_or_else(|| invalid("OCI unpacked byte count overflow"))?;
			if *unpacked_bytes > max_unpacked_bytes {
				return Err(invalid("OCI unpacked byte limit exceeded"));
			}
			fs::write(&target, data)
				.map_err(|_| invalid("failed to write OCI file"))?;
			fs::set_permissions(
				&target,
				fs::Permissions::from_mode(mode & 0o777),
			)
			.map_err(|_| invalid("failed to set OCI file mode"))?;
			set_oci_ownership(&target, uid, gid)?;
		} else if entry_type.is_symlink() {
			let link_name = entry
				.link_name()
				.map_err(|_| invalid("invalid OCI symlink target"))?
				.ok_or_else(|| invalid("missing OCI symlink target"))?
				.into_owned();
			validate_symlink_target(&path, &link_name)?;
			if let Some(parent) = target.parent() {
				fs::create_dir_all(parent).map_err(|_| {
					invalid("failed to create OCI symlink parent")
				})?;
			}
			let _ = fs::remove_file(&target);
			symlink(&link_name, &target)
				.map_err(|_| invalid("failed to create OCI symlink"))?;
			set_oci_ownership(&target, uid, gid)?;
		} else if entry_type.is_hard_link() {
			let link_name = entry
				.link_name()
				.map_err(|_| invalid("invalid OCI hardlink target"))?
				.ok_or_else(|| invalid("missing OCI hardlink target"))?
				.into_owned();
			validate_archive_path(&link_name)?;
			let link_target = rootfs.join(path_to_string(&link_name)?);
			ensure_parent_inside_rootfs(rootfs, &target)?;
			if let Some(parent) = target.parent() {
				fs::create_dir_all(parent).map_err(|_| {
					invalid("failed to create OCI hardlink parent")
				})?;
			}
			fs::hard_link(link_target, &target)
				.map_err(|_| invalid("failed to create OCI hardlink"))?;
			set_oci_ownership(&target, uid, gid)?;
		} else {
			return Err(invalid("unsupported OCI layer entry type"));
		}
	}
	Ok(())
}

#[cfg(target_os = "linux")]
fn set_oci_ownership(
	path: &Path,
	uid: u32,
	gid: u32,
) -> Result<(), ProtocolError> {
	// Bundle materialization is a privileged enclave operation. Keep unit tests
	// and inspection tools usable when they intentionally run without root.
	if !nix::unistd::geteuid().is_root() {
		return Ok(());
	}
	nix::unistd::fchownat(
		nix::fcntl::AT_FDCWD,
		path,
		Some(nix::unistd::Uid::from_raw(uid)),
		Some(nix::unistd::Gid::from_raw(gid)),
		nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
	)
	.map_err(|_| invalid("failed to set OCI entry ownership"))
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn set_oci_ownership(
	_path: &Path,
	_uid: u32,
	_gid: u32,
) -> Result<(), ProtocolError> {
	Ok(())
}

fn handle_whiteout(
	rootfs: &Path,
	normalized: &str,
) -> Result<bool, ProtocolError> {
	let path = Path::new(normalized);
	let Some(file_name) = path.file_name().and_then(|name| name.to_str())
	else {
		return Ok(false);
	};
	if file_name == ".wh..wh..opq" {
		let dir = path.parent().unwrap_or_else(|| Path::new(""));
		let target_dir = rootfs.join(dir);
		if target_dir.exists() {
			for entry in fs::read_dir(&target_dir)
				.map_err(|_| invalid("failed to read opaque whiteout dir"))?
			{
				let entry = entry
					.map_err(|_| invalid("failed to read opaque entry"))?;
				remove_path(&entry.path())?;
			}
		}
		return Ok(true);
	}
	if let Some(removed_name) = file_name.strip_prefix(".wh.") {
		let target =
			path.parent().unwrap_or_else(|| Path::new("")).join(removed_name);
		remove_path(&rootfs.join(target))?;
		return Ok(true);
	}
	Ok(false)
}

fn remove_path(path: &Path) -> Result<(), ProtocolError> {
	if !path.exists() {
		return Ok(());
	}
	let metadata = fs::symlink_metadata(path)
		.map_err(|_| invalid("failed to stat path"))?;
	if metadata.is_dir() {
		fs::remove_dir_all(path)
			.map_err(|_| invalid("failed to remove directory"))?;
	} else {
		fs::remove_file(path).map_err(|_| invalid("failed to remove file"))?;
	}
	Ok(())
}

fn verify_descriptor_graph(
	blobs: &HashMap<String, Vec<u8>>,
	pivot: &PivotOciImageConfigV2,
) -> Result<VerifiedOciImage, ProtocolError> {
	let manifest_bytes = verified_blob(blobs, &pivot.digest)?;
	let manifest: ImageManifest = serde_json::from_slice(manifest_bytes)
		.map_err(|_| invalid("approved digest is not an OCI image manifest"))?;
	if let Some(media_type) = manifest.media_type()
		&& *media_type != MediaType::ImageManifest
	{
		return Err(invalid("approved digest is not an OCI image manifest"));
	}
	if manifest.schema_version() != 2 {
		return Err(invalid("OCI image manifest schemaVersion must be 2"));
	}

	let config_descriptor = manifest.config();
	require_media_type(config_descriptor, MediaType::ImageConfig)?;
	let config_digest = oci_digest_from_descriptor(config_descriptor)?;
	let config_bytes = verified_descriptor_blob(blobs, config_descriptor)?;
	let image_config: ImageConfiguration = serde_json::from_slice(config_bytes)
		.map_err(|_| invalid("OCI image config is invalid JSON"))?;
	validate_image_config(&image_config, pivot)?;

	let mut layers = Vec::with_capacity(manifest.layers().len());
	for descriptor in manifest.layers() {
		let gzip = match descriptor.media_type() {
			MediaType::ImageLayer => false,
			MediaType::ImageLayerGzip => true,
			_ => return Err(invalid("unsupported OCI layer media type")),
		};
		let digest = oci_digest_from_descriptor(descriptor)?;
		verified_descriptor_blob(blobs, descriptor)?;
		layers.push(VerifiedLayer { digest, gzip });
	}

	let diff_ids = image_config.rootfs().diff_ids().clone();
	if diff_ids.len() != layers.len() {
		return Err(invalid("OCI rootfs diff_ids do not match layer count"));
	}
	for diff_id in &diff_ids {
		validate_oci_digest_string(diff_id)?;
	}

	let config = image_config.config().as_ref();
	let entrypoint =
		config.and_then(|c| c.entrypoint().clone()).unwrap_or_default();
	let cmd = config.and_then(|c| c.cmd().clone()).unwrap_or_default();
	let env = config.and_then(|c| c.env().clone()).unwrap_or_default();
	let user = config
		.and_then(|c| c.user().clone())
		.filter(|user| !user.is_empty())
		.unwrap_or_else(|| "0".to_string());
	let working_dir = config
		.and_then(|c| c.working_dir().clone())
		.filter(|dir| !dir.is_empty())
		.unwrap_or_else(|| "/".to_string());
	let volumes = config.and_then(|c| c.volumes().clone()).unwrap_or_default();
	let exposed_ports =
		config.and_then(|c| c.exposed_ports().clone()).unwrap_or_default();

	Ok(VerifiedOciImage {
		digest: pivot.digest.clone(),
		config_digest,
		layers,
		diff_ids,
		entrypoint,
		cmd,
		env,
		working_dir,
		user,
		volumes,
		exposed_ports,
	})
}

fn validate_image_config(
	image_config: &ImageConfiguration,
	pivot: &PivotOciImageConfigV2,
) -> Result<(), ProtocolError> {
	if image_config.os().to_string() != "linux" {
		return Err(invalid("OCI image config os must be linux"));
	}
	if image_config.architecture().to_string() != "amd64" {
		return Err(invalid("OCI image config architecture must be amd64"));
	}
	if image_config.os().to_string() != pivot.platform.os
		|| image_config.architecture().to_string()
			!= pivot.platform.architecture
	{
		return Err(invalid("OCI image config platform differs from manifest"));
	}
	if image_config.rootfs().typ() != "layers" {
		return Err(invalid("OCI rootfs type must be layers"));
	}

	if let Some(config) = image_config.config() {
		if let Some(working_dir) = config.working_dir()
			&& !working_dir.is_empty()
		{
			validate_absolute_rootfs_path(working_dir)?;
		}
		if let Some(volumes) = config.volumes() {
			let mut seen = BTreeSet::new();
			for volume in volumes {
				validate_volume_path(volume)?;
				if !seen.insert(volume) {
					return Err(invalid("duplicate OCI volume path"));
				}
			}
		}
		if let Some(exposed_ports) = config.exposed_ports() {
			for port in exposed_ports {
				validate_exposed_port(port)?;
			}
		}
	}

	Ok(())
}

fn verified_descriptor_blob<'a>(
	blobs: &'a HashMap<String, Vec<u8>>,
	descriptor: &Descriptor,
) -> Result<&'a [u8], ProtocolError> {
	let digest = oci_digest_from_descriptor(descriptor)?;
	let blob = verified_blob(blobs, &digest)?;
	if blob.len() as u64 != descriptor.size() {
		return Err(invalid("OCI descriptor size mismatch"));
	}
	Ok(blob)
}

fn verified_blob<'a>(
	blobs: &'a HashMap<String, Vec<u8>>,
	digest: &OciDigest,
) -> Result<&'a [u8], ProtocolError> {
	let blob = blobs
		.get(digest.hex())
		.ok_or_else(|| invalid("required OCI blob is missing"))?;
	let actual = qos_hex::encode(&qos_crypto::sha_256(blob));
	if actual != digest.hex() {
		return Err(invalid("OCI blob digest mismatch"));
	}
	Ok(blob)
}

fn require_media_type(
	descriptor: &Descriptor,
	expected: MediaType,
) -> Result<(), ProtocolError> {
	if *descriptor.media_type() != expected {
		return Err(invalid("unexpected OCI descriptor media type"));
	}
	Ok(())
}

fn oci_digest_from_descriptor(
	descriptor: &Descriptor,
) -> Result<OciDigest, ProtocolError> {
	OciDigest::new(descriptor.digest().to_string()).map_err(invalid)
}

fn validate_archive_path(path: &Path) -> Result<(), ProtocolError> {
	if path.is_absolute() {
		return Err(invalid("OCI archive path is absolute"));
	}
	for component in path.components() {
		match component {
			Component::Normal(_) | Component::CurDir => {}
			Component::ParentDir
			| Component::RootDir
			| Component::Prefix(_) => {
				return Err(invalid("OCI archive path escapes layout root"));
			}
		}
	}
	Ok(())
}

fn path_to_string(path: &Path) -> Result<String, ProtocolError> {
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::Normal(part) => {
				let Some(part) = part.to_str() else {
					return Err(invalid("OCI archive path is not UTF-8"));
				};
				parts.push(part);
			}
			Component::CurDir => {}
			Component::ParentDir
			| Component::RootDir
			| Component::Prefix(_) => {
				return Err(invalid("OCI archive path escapes layout root"));
			}
		}
	}
	if parts.is_empty() {
		return Err(invalid("OCI archive path is empty"));
	}
	Ok(parts.join("/"))
}

fn validate_sha256_hex(hex: &str) -> Result<(), ProtocolError> {
	if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
		return Err(invalid("OCI blob path does not contain SHA-256 hex"));
	}
	if hex.bytes().any(|b| b.is_ascii_uppercase()) {
		return Err(invalid("OCI blob path digest must be lowercase"));
	}
	Ok(())
}

fn validate_oci_digest_string(digest: &str) -> Result<(), ProtocolError> {
	OciDigest::new(digest.to_string()).map(|_| ()).map_err(invalid)
}

fn validate_volume_path(path: &str) -> Result<(), ProtocolError> {
	validate_absolute_rootfs_path(path)?;
	if path == "/" || QOS_COMPAT_PATHS.contains(&path) {
		return Err(invalid("OCI volume cannot mask QOS-managed paths"));
	}
	if path == "/tmp" || path == "/run" || path == "/dev/shm" {
		return Ok(());
	}
	if QOS_COMPAT_PATHS.iter().any(|qos_path| qos_path.starts_with(path)) {
		return Err(invalid("OCI volume cannot mask QOS-managed paths"));
	}
	Ok(())
}

fn validate_absolute_rootfs_path(path: &str) -> Result<(), ProtocolError> {
	if !path.starts_with('/') {
		return Err(invalid("OCI path must be absolute"));
	}
	let path = PathBuf::from(path);
	for component in path.components() {
		match component {
			Component::RootDir | Component::Normal(_) => {}
			Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
				return Err(invalid("OCI path escapes rootfs"));
			}
		}
	}
	Ok(())
}

fn validate_exposed_port(port: &str) -> Result<(), ProtocolError> {
	let (number, proto) = port.split_once('/').unwrap_or((port, "tcp"));
	if proto != "tcp" && proto != "udp" {
		return Err(invalid("OCI ExposedPorts protocol must be tcp or udp"));
	}
	let number = number
		.parse::<u16>()
		.map_err(|_| invalid("OCI ExposedPorts port is invalid"))?;
	if number == 0 {
		return Err(invalid("OCI ExposedPorts port must be non-zero"));
	}
	Ok(())
}

fn ensure_parent_inside_rootfs(
	rootfs: &Path,
	target: &Path,
) -> Result<(), ProtocolError> {
	let Some(parent) = target.parent() else {
		return Err(invalid("OCI target has no parent"));
	};
	let relative_parent = parent
		.strip_prefix(rootfs)
		.map_err(|_| invalid("OCI target escapes rootfs"))?;
	let mut current = rootfs.to_path_buf();
	for component in relative_parent.components() {
		if let Component::Normal(part) = component {
			current.push(part);
			if let Ok(metadata) = fs::symlink_metadata(&current)
				&& metadata.file_type().is_symlink()
			{
				return Err(invalid("OCI path traverses existing symlink"));
			}
		}
	}
	Ok(())
}

fn validate_symlink_target(
	link_path: &Path,
	target: &Path,
) -> Result<(), ProtocolError> {
	// Absolute links are rooted at the container root once pivoted. Relative
	// links may contain `..` as long as resolving them from the link's parent
	// does not walk above that root.
	let mut depth = if target.is_absolute() {
		0
	} else {
		link_path.parent().map_or(0, |parent| parent.components().count())
	};
	for component in target.components() {
		match component {
			Component::Normal(_) => depth += 1,
			Component::CurDir | Component::RootDir => {}
			Component::ParentDir if depth > 0 => depth -= 1,
			Component::ParentDir | Component::Prefix(_) => {
				return Err(invalid("OCI symlink target escapes rootfs"));
			}
		}
	}
	Ok(())
}

fn create_runtime_mount_points(
	rootfs: &Path,
	verified: &VerifiedOciImage,
) -> Result<(), ProtocolError> {
	let mut mounts = BTreeSet::new();
	for dir in ["/tmp", "/run", "/dev/shm"] {
		mounts.insert(dir.to_string());
	}
	for volume in &verified.volumes {
		mounts.insert(volume.clone());
	}
	for mount in mounts {
		validate_volume_path(&mount)?;
		let path = rootfs.join(mount.trim_start_matches('/'));
		fs::create_dir_all(&path)
			.map_err(|_| invalid("failed to create builtin OCI tmpfs path"))?;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).map_err(
			|_| invalid("failed to set builtin OCI tmpfs path mode"),
		)?;
	}
	Ok(())
}

fn reject_unsupported_pax<R: Read>(
	entry: &mut tar::Entry<'_, R>,
) -> Result<(), ProtocolError> {
	if let Some(extensions) = entry
		.pax_extensions()
		.map_err(|_| invalid("invalid OCI PAX extension"))?
	{
		for extension in extensions {
			let extension =
				extension.map_err(|_| invalid("invalid OCI PAX extension"))?;
			let key = extension
				.key()
				.map_err(|_| invalid("invalid OCI PAX extension key"))?;
			if key.starts_with("SCHILY.xattr.")
				|| key.starts_with("GNU.sparse.")
				|| key.starts_with("LIBARCHIVE.xattr.")
			{
				return Err(invalid(
					"OCI PAX xattrs and sparse files are unsupported",
				));
			}
		}
	}
	Ok(())
}

fn materialize_qos_files(
	handles: &Handles,
	rootfs: &Path,
) -> Result<(), ProtocolError> {
	for (path, bytes) in [
		("/qos.quorum.key", handles.quorum_key_bytes()?),
		("/qos.ephemeral.key", handles.ephemeral_key_bytes()?),
		("/qos.manifest", handles.manifest_envelope_bytes()?),
	] {
		let target = rootfs.join(path.trim_start_matches('/'));
		if let Some(parent) = target.parent() {
			fs::create_dir_all(parent)
				.map_err(|_| invalid("failed to create QOS file parent"))?;
		}
		fs::write(&target, bytes)
			.map_err(|_| invalid("failed to materialize QOS file"))?;
		fs::set_permissions(&target, fs::Permissions::from_mode(0o444))
			.map_err(|_| invalid("failed to set QOS file mode"))?;
	}
	Ok(())
}

fn build_runtime_spec(
	pivot: &PivotOciImageConfigV2,
	verified: &VerifiedOciImage,
	rootfs: &Path,
	argv: &[String],
	env: &[(String, String)],
	cwd: &str,
) -> Result<Spec, ProtocolError> {
	let mut spec = pivot.runtime.clone().unwrap_or_default();
	if spec.linux().as_ref().is_some_and(|linux| linux.seccomp().is_some()) {
		return Err(invalid(
			"OCI seccomp profiles are unavailable in the static enclave runtime",
		));
	}
	// An enclave is already a network boundary. Keep its network namespace by
	// default so loopback and the VSOCK/TCP bridge work; an approved runtime
	// spec can explicitly request a separate network namespace.
	if pivot.runtime.is_none()
		&& let Some(linux) = spec.linux_mut().as_mut()
		&& let Some(namespaces) = linux.namespaces_mut().as_mut()
	{
		namespaces
			.retain(|namespace| namespace.typ() != LinuxNamespaceType::Network);
	}
	let readonly = pivot
		.runtime
		.as_ref()
		.and_then(|runtime| runtime.root().as_ref())
		.and_then(|root| root.readonly())
		.unwrap_or(false);
	let root = RootBuilder::default()
		.path(rootfs)
		.readonly(readonly)
		.build()
		.map_err(|_| invalid("failed to configure OCI rootfs"))?;
	spec.set_root(Some(root));

	let mut process: Process = spec.process().clone().unwrap_or_default();
	if pivot.runtime.is_none() {
		process.set_user(resolve_image_user(rootfs, &verified.user)?);
	}
	process.set_args(Some(argv.to_vec()));
	process.set_env(Some(
		env.iter().map(|(name, value)| format!("{name}={value}")).collect(),
	));
	process.set_cwd(PathBuf::from(cwd));
	spec.set_process(Some(process));

	let mut mounts = spec.mounts().clone().unwrap_or_default();
	let mut destinations = mounts
		.iter()
		.map(|mount| mount.destination().clone())
		.collect::<BTreeSet<_>>();
	for destination in ["/tmp", "/run", "/dev/shm"]
		.into_iter()
		.chain(verified.volumes.iter().map(String::as_str))
	{
		let destination = PathBuf::from(destination);
		if destinations.insert(destination.clone()) {
			let mount = MountBuilder::default()
				.destination(destination)
				.typ("tmpfs")
				.source("tmpfs")
				.options(vec![
					"nosuid".to_string(),
					"nodev".to_string(),
					"noexec".to_string(),
					"mode=1777".to_string(),
					format!("size={}", pivot.limits.max_unpacked_bytes),
				])
				.build()
				.map_err(|_| invalid("failed to configure OCI tmpfs mount"))?;
			mounts.push(mount);
		}
	}
	spec.set_mounts(Some(mounts));
	Ok(spec)
}

fn resolve_image_user(
	rootfs: &Path,
	value: &str,
) -> Result<User, ProtocolError> {
	let (user_value, group_value) = value
		.split_once(':')
		.map_or((value, None), |(user, group)| (user, Some(group)));
	let passwd =
		fs::read_to_string(rootfs.join("etc/passwd")).unwrap_or_default();
	let groups =
		fs::read_to_string(rootfs.join("etc/group")).unwrap_or_default();

	let (uid, default_gid, username) =
		if let Ok(uid) = user_value.parse::<u32>() {
			(uid, 0, None)
		} else if user_value == "root" {
			(0, 0, Some("root".to_string()))
		} else {
			let (uid, gid) = passwd
				.lines()
				.find_map(|line| {
					let mut fields = line.split(':');
					let name = fields.next()?;
					fields.next()?;
					let uid = fields.next()?.parse::<u32>().ok()?;
					let gid = fields.next()?.parse::<u32>().ok()?;
					(name == user_value).then_some((uid, gid))
				})
				.ok_or_else(|| {
					invalid("OCI image user is missing from /etc/passwd")
				})?;
			(uid, gid, Some(user_value.to_string()))
		};

	let gid = match group_value {
		None | Some("") => default_gid,
		Some(group) => {
			if let Ok(gid) = group.parse::<u32>() {
				gid
			} else if group == "root" {
				0
			} else {
				groups
					.lines()
					.find_map(|line| {
						let mut fields = line.split(':');
						let name = fields.next()?;
						fields.next()?;
						let gid = fields.next()?.parse::<u32>().ok()?;
						(name == group).then_some(gid)
					})
					.ok_or_else(|| {
						invalid("OCI image group is missing from /etc/group")
					})?
			}
		}
	};

	let mut user = User::default();
	user.set_uid(uid);
	user.set_gid(gid);
	user.set_username(username);
	Ok(user)
}

fn derive_argv(
	pivot: &PivotOciImageConfigV2,
	verified: &VerifiedOciImage,
) -> Result<Vec<String>, ProtocolError> {
	let argv = pivot
		.args
		.clone()
		.or_else(|| {
			pivot.runtime.as_ref().and_then(|spec| {
				spec.process()
					.as_ref()
					.and_then(|process| process.args().clone())
			})
		})
		.unwrap_or_else(|| {
			let mut argv = Vec::with_capacity(
				verified.entrypoint.len() + verified.cmd.len(),
			);
			argv.extend(verified.entrypoint.clone());
			argv.extend(verified.cmd.clone());
			argv
		});
	if argv.is_empty() {
		return Err(invalid("OCI image does not define argv"));
	}
	Ok(argv)
}

fn derive_env(
	pivot: &PivotOciImageConfigV2,
	verified: &VerifiedOciImage,
) -> Result<Vec<(String, String)>, ProtocolError> {
	let mut env = std::collections::BTreeMap::new();
	for entry in &verified.env {
		let Some((name, value)) = entry.split_once('=') else {
			return Err(invalid("OCI image env entry is missing '='"));
		};
		env.insert(name.to_string(), value.to_string());
	}
	if let Some(runtime_env) = pivot
		.runtime
		.as_ref()
		.and_then(|spec| spec.process().as_ref())
		.and_then(|process| process.env().as_ref())
	{
		for entry in runtime_env {
			let Some((name, value)) = entry.split_once('=') else {
				return Err(invalid("OCI runtime env entry is missing '='"));
			};
			env.insert(name.to_string(), value.to_string());
		}
	}
	for (name, value) in pivot.env.iter() {
		let Some(value) = value.as_plain_value() else {
			return Err(ProtocolError::InvalidPivotEnv(
				"unsupported pivot env value".to_string(),
			));
		};
		env.insert(name.to_string(), value.to_string());
	}
	Ok(env.into_iter().collect())
}

fn derive_cwd(
	pivot: &PivotOciImageConfigV2,
	verified: &VerifiedOciImage,
) -> Result<String, ProtocolError> {
	let cwd = pivot
		.runtime
		.as_ref()
		.and_then(|spec| spec.process().as_ref())
		.map(|process| process.cwd().to_string_lossy().into_owned())
		.unwrap_or_else(|| verified.working_dir.clone());
	validate_absolute_rootfs_path(&cwd)?;
	Ok(cwd)
}

fn invalid(message: impl Into<String>) -> ProtocolError {
	ProtocolError::InvalidOciImage(message.into())
}

#[cfg(test)]
mod tests {
	use std::{
		io::Cursor,
		sync::atomic::{AtomicUsize, Ordering},
	};

	use tar::{Builder, Header};

	use super::*;
	use crate::{
		handles::Handles,
		protocol::services::boot::{
			ManifestEnvelopeV2, ManifestSet, ManifestV2, ManifestVersion,
			Namespace, NitroConfig, OciPlatform, OciRuntimeLimits,
			PivotConfigV2, PivotEnv, PivotKind, RestartPolicy, ShareSet,
		},
	};
	use qos_p256::P256Pair;

	static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

	struct Fixture {
		archive: Vec<u8>,
		pivot: PivotOciImageConfigV2,
		manifest_hex: String,
		config_hex: String,
		layer_hex: String,
	}

	fn test_handles() -> Handles {
		let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
		let root = std::env::temp_dir()
			.join(format!("qos-oci-test-{}-{id}", std::process::id()));
		Handles::new_with_oci_dir(
			root.join("ephemeral").to_string_lossy().into_owned(),
			root.join("quorum").to_string_lossy().into_owned(),
			root.join("manifest").to_string_lossy().into_owned(),
			root.join("pivot").to_string_lossy().into_owned(),
			root.join("oci"),
		)
	}

	fn sha256_hex(bytes: &[u8]) -> String {
		qos_hex::encode(&qos_crypto::sha_256(bytes))
	}

	fn append_file(builder: &mut Builder<Vec<u8>>, path: &str, data: &[u8]) {
		let mut header = Header::new_gnu();
		header.set_size(data.len() as u64);
		header.set_mode(0o444);
		header.set_uid(0);
		header.set_gid(0);
		header.set_cksum();
		builder.append_data(&mut header, path, Cursor::new(data)).unwrap();
	}

	fn layer_tar() -> Vec<u8> {
		let mut builder = Builder::new(Vec::new());
		append_file(&mut builder, "app", b"hello");
		builder.into_inner().unwrap()
	}

	fn fixture() -> Fixture {
		let layer = layer_tar();
		let layer_hex = sha256_hex(&layer);
		let layer_digest = format!("sha256:{layer_hex}");

		let config = format!(
			r#"{{
				"architecture":"amd64",
				"os":"linux",
				"config":{{
					"User":"root",
					"Entrypoint":["/app"],
					"Env":["A=B"],
					"WorkingDir":"/",
					"Volumes":{{"/tmp/data":{{}}}},
					"ExposedPorts":{{"8080/tcp":{{}}}}
				}},
				"rootfs":{{"type":"layers","diff_ids":["{layer_digest}"]}}
			}}"#
		)
		.into_bytes();
		let config_hex = sha256_hex(&config);
		let config_digest = format!("sha256:{config_hex}");

		let manifest = format!(
			r#"{{
				"schemaVersion":2,
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{{
					"mediaType":"application/vnd.oci.image.config.v1+json",
					"digest":"{config_digest}",
					"size":{}
				}},
				"layers":[{{
					"mediaType":"application/vnd.oci.image.layer.v1.tar",
					"digest":"{layer_digest}",
					"size":{}
				}}]
			}}"#,
			config.len(),
			layer.len()
		)
		.into_bytes();
		let manifest_hex = sha256_hex(&manifest);
		let manifest_digest = format!("sha256:{manifest_hex}");

		let mut builder = Builder::new(Vec::new());
		append_file(
			&mut builder,
			"oci-layout",
			br#"{"imageLayoutVersion":"1.0.0"}"#,
		);
		append_file(
			&mut builder,
			"index.json",
			br#"{"schemaVersion":2,"manifests":[]}"#,
		);
		append_file(
			&mut builder,
			&format!("blobs/sha256/{manifest_hex}"),
			&manifest,
		);
		append_file(
			&mut builder,
			&format!("blobs/sha256/{config_hex}"),
			&config,
		);
		append_file(&mut builder, &format!("blobs/sha256/{layer_hex}"), &layer);
		let archive = builder.into_inner().unwrap();

		let pivot = PivotOciImageConfigV2 {
			r#type: PivotKind::OciImage,
			digest: OciDigest::new(manifest_digest).unwrap(),
			platform: OciPlatform {
				os: "linux".to_string(),
				architecture: "amd64".to_string(),
			},
			restart: RestartPolicy::Never,
			args: None,
			env: PivotEnv::new(),
			debug_mode: false,
			bridge_config: vec![],
			limits: OciRuntimeLimits {
				max_compressed_bytes: 1024 * 1024,
				max_unpacked_bytes: 1024 * 1024,
				max_entries: 1024,
			},
			runtime: None,
		};

		Fixture { archive, pivot, manifest_hex, config_hex, layer_hex }
	}

	#[test]
	fn imports_protocol_supplied_layout_archive() {
		let Fixture { archive, pivot, manifest_hex, config_hex, layer_hex } =
			fixture();
		let handles = test_handles();

		let verified =
			import_oci_layout_archive(&handles, &pivot, &archive).unwrap();

		assert_eq!(verified.digest, pivot.digest);
		assert_eq!(verified.config_digest.hex(), config_hex);
		assert_eq!(verified.layers[0].digest.hex(), layer_hex);
		assert!(handles.oci_blob_exists(&manifest_hex));
		assert!(handles.oci_blob_exists(&config_hex));
		assert!(handles.oci_blob_exists(&layer_hex));
		assert_eq!(verified.entrypoint, vec!["/app"]);
		assert_eq!(verified.volumes, vec!["/tmp/data"]);
		assert_eq!(verified.exposed_ports, vec!["8080/tcp"]);
	}

	#[test]
	fn prepares_runtime_bundle_from_imported_content() {
		let Fixture { archive, pivot, .. } = fixture();
		let handles = test_handles();
		import_oci_layout_archive(&handles, &pivot, &archive).unwrap();
		let quorum = P256Pair::generate().unwrap();
		let ephemeral = P256Pair::generate().unwrap();
		handles.put_quorum_key(&quorum).unwrap();
		handles.put_ephemeral_key(&ephemeral).unwrap();
		handles
			.put_manifest_envelope(ManifestEnvelopeV2 {
				manifest: ManifestV2 {
					version: ManifestVersion::V2,
					namespace: Namespace {
						name: "oci-test".to_string(),
						nonce: 1,
						quorum_key: quorum.public_key().to_bytes(),
					},
					pivot: PivotConfigV2::OciImage(pivot.clone()),
					manifest_set: ManifestSet { threshold: 1, members: vec![] },
					share_set: ShareSet { threshold: 1, members: vec![] },
					enclave: NitroConfig {
						pcr0: vec![],
						pcr1: vec![],
						pcr2: vec![],
						pcr3: vec![],
						aws_root_certificate: vec![],
						qos_commit: "test".to_string(),
					},
				},
				manifest_set_approvals: vec![],
				share_set_approvals: vec![],
			})
			.unwrap();

		let bundle = prepare_oci_runtime_bundle(&handles, &pivot).unwrap();

		assert_eq!(bundle.argv, vec!["/app"]);
		assert_eq!(bundle.env, vec![("A".to_string(), "B".to_string())]);
		assert!(bundle.rootfs.join("app").exists());
		assert!(bundle.rootfs.join("tmp").exists());
		assert!(bundle.rootfs.join("run").exists());
		assert!(bundle.rootfs.join("dev/shm").exists());
		assert!(bundle.rootfs.join("tmp/data").exists());
		assert!(bundle.rootfs.join("qos.quorum.key").exists());
		assert!(bundle.rootfs.join("qos.ephemeral.key").exists());
		assert!(bundle.rootfs.join("qos.manifest").exists());

		let spec = Spec::load(bundle.bundle_dir.join("config.json")).unwrap();
		assert_eq!(spec, bundle.spec);
		assert_eq!(spec.root().as_ref().unwrap().path(), &bundle.rootfs);
	}

	#[test]
	fn preserves_approved_runtime_configuration() {
		let Fixture { archive, mut pivot, .. } = fixture();
		let handles = test_handles();
		let verified =
			import_oci_layout_archive(&handles, &pivot, &archive).unwrap();
		let mut runtime = Spec::default();
		runtime.set_hostname(Some("approved-hostname".to_string()));
		let process = runtime.process_mut().as_mut().unwrap();
		process.set_args(Some(vec!["/runtime-app".to_string()]));
		process.set_env(Some(vec!["RUNTIME=yes".to_string()]));
		process.set_cwd(PathBuf::from("/runtime"));
		pivot.runtime = Some(runtime);

		let rootfs = handles.oci_rootfs_dir(pivot.digest.hex());
		fs::create_dir_all(&rootfs).unwrap();
		let argv = derive_argv(&pivot, &verified).unwrap();
		let env = derive_env(&pivot, &verified).unwrap();
		let cwd = derive_cwd(&pivot, &verified).unwrap();
		let spec =
			build_runtime_spec(&pivot, &verified, &rootfs, &argv, &env, &cwd)
				.unwrap();

		assert_eq!(spec.hostname().as_deref(), Some("approved-hostname"));
		assert_eq!(argv, vec!["/runtime-app"]);
		assert!(env.contains(&("RUNTIME".to_string(), "yes".to_string())));
		assert_eq!(cwd, "/runtime");
		assert_eq!(spec.root().as_ref().unwrap().path(), &rootfs);
	}

	#[test]
	fn resolves_named_image_users_and_groups() {
		let handles = test_handles();
		let rootfs = handles.oci_rootfs_dir("users");
		fs::create_dir_all(rootfs.join("etc")).unwrap();
		fs::write(
			rootfs.join("etc/passwd"),
			"root:x:0:0:root:/root:/bin/sh\napp:x:1001:1002::/app:/bin/sh\n",
		)
		.unwrap();
		fs::write(rootfs.join("etc/group"), "root:x:0:\nappgroup:x:1003:\n")
			.unwrap();

		let user = resolve_image_user(&rootfs, "app:appgroup").unwrap();
		assert_eq!(user.uid(), 1001);
		assert_eq!(user.gid(), 1003);
		assert_eq!(user.username().as_deref(), Some("app"));
	}

	#[test]
	fn rejects_missing_required_blob() {
		let Fixture { pivot, .. } = fixture();
		let mut builder = Builder::new(Vec::new());
		append_file(
			&mut builder,
			"oci-layout",
			br#"{"imageLayoutVersion":"1.0.0"}"#,
		);
		append_file(
			&mut builder,
			"index.json",
			br#"{"schemaVersion":2,"manifests":[]}"#,
		);
		let archive = builder.into_inner().unwrap();

		let err = import_oci_layout_archive(&test_handles(), &pivot, &archive)
			.unwrap_err();

		assert!(matches!(err, ProtocolError::InvalidOciImage(_)));
	}

	#[test]
	fn rejects_invalid_blob_path() {
		let Fixture { archive: _, pivot, .. } = fixture();
		let mut builder = Builder::new(Vec::new());
		append_file(
			&mut builder,
			"oci-layout",
			br#"{"imageLayoutVersion":"1.0.0"}"#,
		);
		append_file(
			&mut builder,
			"index.json",
			br#"{"schemaVersion":2,"manifests":[]}"#,
		);
		append_file(&mut builder, "blobs/sha256/not-a-digest", b"bad");
		let archive = builder.into_inner().unwrap();

		let err = import_oci_layout_archive(&test_handles(), &pivot, &archive)
			.unwrap_err();

		assert!(matches!(err, ProtocolError::InvalidOciImage(_)));
	}

	#[test]
	fn rejects_pax_xattrs_in_layout_archive() {
		let Fixture { pivot, .. } = fixture();
		let mut builder = Builder::new(Vec::new());
		append_file(
			&mut builder,
			"oci-layout",
			br#"{"imageLayoutVersion":"1.0.0"}"#,
		);
		append_file(
			&mut builder,
			"index.json",
			br#"{"schemaVersion":2,"manifests":[]}"#,
		);
		builder
			.append_pax_extensions([(
				"SCHILY.xattr.security.capability",
				b"unsupported".as_slice(),
			)])
			.unwrap();
		append_file(
			&mut builder,
			"blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			b"bad",
		);
		let archive = builder.into_inner().unwrap();

		let err = import_oci_layout_archive(&test_handles(), &pivot, &archive)
			.unwrap_err();

		assert!(matches!(err, ProtocolError::InvalidOciImage(_)));
	}

	#[test]
	fn applies_oci_whiteouts() {
		let handles = test_handles();
		let rootfs = handles.oci_rootfs_dir("whiteout");
		fs::create_dir_all(rootfs.join("dir")).unwrap();
		fs::write(rootfs.join("dir/old"), b"old").unwrap();
		fs::write(rootfs.join("dir/keep"), b"keep").unwrap();

		let mut builder = Builder::new(Vec::new());
		append_file(&mut builder, "dir/.wh.old", b"");
		append_file(&mut builder, "dir/new", b"new");
		let layer = builder.into_inner().unwrap();
		let mut unpacked_bytes = 0;
		let mut entries = 0;

		apply_layer(
			&rootfs,
			&layer,
			1024 * 1024,
			1024,
			&mut unpacked_bytes,
			&mut entries,
		)
		.unwrap();

		assert!(!rootfs.join("dir/old").exists());
		assert!(rootfs.join("dir/keep").exists());
		assert_eq!(fs::read(rootfs.join("dir/new")).unwrap(), b"new");
	}

	#[test]
	fn accepts_container_rooted_and_safe_parent_symlinks() {
		validate_symlink_target(
			Path::new("usr/lib/libexample.so"),
			Path::new("../../lib/libexample.so.1"),
		)
		.unwrap();
		validate_symlink_target(
			Path::new("lib/libc.so"),
			Path::new("/lib/libc.so.6"),
		)
		.unwrap();
	}

	#[test]
	fn rejects_symlinks_that_walk_above_container_root() {
		let error = validate_symlink_target(
			Path::new("lib/libexample.so"),
			Path::new("../../../../host"),
		)
		.unwrap_err();
		assert!(matches!(error, ProtocolError::InvalidOciImage(_)));
	}

	#[test]
	fn rejects_volume_that_masks_qos_files() {
		let mut fixture = fixture();
		let layer = layer_tar();
		let layer_hex = sha256_hex(&layer);
		let layer_digest = format!("sha256:{layer_hex}");
		let config = format!(
			r#"{{
				"architecture":"amd64",
				"os":"linux",
				"config":{{"User":"root","Entrypoint":["/app"],"Volumes":{{"/":{{}}}}}},
				"rootfs":{{"type":"layers","diff_ids":["{layer_digest}"]}}
			}}"#
		)
		.into_bytes();
		let config_hex = sha256_hex(&config);
		let manifest = format!(
			r#"{{
				"schemaVersion":2,
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_hex}","size":{}}},
				"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]
			}}"#,
			config.len(),
			layer.len()
		)
		.into_bytes();
		let manifest_hex = sha256_hex(&manifest);
		fixture.pivot.digest =
			OciDigest::new(format!("sha256:{manifest_hex}")).unwrap();
		let mut builder = Builder::new(Vec::new());
		append_file(
			&mut builder,
			"oci-layout",
			br#"{"imageLayoutVersion":"1.0.0"}"#,
		);
		append_file(
			&mut builder,
			"index.json",
			br#"{"schemaVersion":2,"manifests":[]}"#,
		);
		append_file(
			&mut builder,
			&format!("blobs/sha256/{manifest_hex}"),
			&manifest,
		);
		append_file(
			&mut builder,
			&format!("blobs/sha256/{config_hex}"),
			&config,
		);
		append_file(&mut builder, &format!("blobs/sha256/{layer_hex}"), &layer);
		let archive = builder.into_inner().unwrap();

		let err = import_oci_layout_archive(
			&test_handles(),
			&fixture.pivot,
			&archive,
		)
		.unwrap_err();

		assert!(matches!(err, ProtocolError::InvalidOciImage(_)));
	}
}
