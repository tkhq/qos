//! Safe construction of writable root filesystems from verified OCI layers.

use std::{
	collections::{HashMap, HashSet, VecDeque},
	ffi::CString,
	fs::{self, OpenOptions},
	io::{Cursor, Read},
	os::unix::{ffi::OsStrExt, fs::PermissionsExt},
	path::{Component, Path, PathBuf},
};

use crate::{
	oci_image::{VerifiedOciImage, VerifiedProcess, decompress_layer},
	protocol::ProtocolError,
};

const MAX_LAYER_ENTRIES: usize = 262_144;
const MAX_LAYER_PATH_BYTES: usize = 4_096;
const DEFAULT_PATH: &str =
	"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn invalid(message: impl Into<String>) -> ProtocolError {
	ProtocolError::InvalidOci(message.into())
}

/// Numeric process identity resolved from the verified image root filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
	/// Effective user ID.
	pub uid: u32,
	/// Effective group ID.
	pub gid: u32,
	/// Supplementary group IDs.
	pub additional_gids: Vec<u32>,
}

/// Fully validated process configuration ready for an OCI runtime spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProcess {
	/// Entrypoint followed by command arguments.
	pub args: Vec<String>,
	/// De-duplicated environment entries.
	pub env: Vec<String>,
	/// Absolute container working directory.
	pub cwd: PathBuf,
	/// Numeric image identity.
	pub identity: ProcessIdentity,
	/// Validated Linux stop signal number.
	pub stop_signal: i32,
}

/// Apply all verified image layers into a fresh, caller-owned directory.
///
/// # Errors
///
/// Returns an error for an unsafe archive entry, unsupported metadata, or any
/// filesystem operation that cannot preserve required image semantics.
pub fn build_rootfs(
	image: &VerifiedOciImage,
	rootfs: &Path,
) -> Result<RuntimeProcess, ProtocolError> {
	if rootfs.exists() {
		return Err(invalid("OCI rootfs already exists"));
	}
	fs::create_dir_all(rootfs)
		.map_err(|_| invalid("failed to create OCI rootfs"))?;
	for layer in &image.layers {
		let tar = decompress_layer(&layer.blob, layer.compression)?;
		apply_layer(rootfs, &tar)?;
	}
	resolve_process(rootfs, &image.process)
}

/// Prepare a directory bind-mount target without following image symlinks.
///
/// # Errors
///
/// Returns an error when the target escapes the rootfs or is not a directory.
pub fn prepare_directory_target(
	rootfs: &Path,
	container_path: &Path,
) -> Result<(), ProtocolError> {
	let relative = container_relative(container_path)?;
	ensure_safe_parents(rootfs, &relative)?;
	let target = rootfs.join(relative);
	match fs::symlink_metadata(&target) {
		Ok(metadata) if metadata.is_dir() => Ok(()),
		Ok(_) => Err(invalid("OCI volume target is not a directory")),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			fs::create_dir(&target)
				.map_err(|_| invalid("failed to create OCI volume target"))?;
			fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
				.map_err(|_| invalid("failed to set OCI volume target mode"))
		}
		Err(_) => Err(invalid("failed to inspect OCI volume target")),
	}
}

fn container_relative(path: &Path) -> Result<PathBuf, ProtocolError> {
	normalized_container_path(&path.to_string_lossy())?
		.strip_prefix("/")
		.map(Path::to_path_buf)
		.map_err(|_| invalid("OCI mount target is not absolute"))
}

#[derive(Clone)]
struct Metadata {
	path: PathBuf,
	mode: u32,
	uid: u32,
	gid: u32,
	mtime: i64,
	mtime_nsec: i64,
	xattrs: Vec<(CString, Vec<u8>)>,
	symlink: bool,
}

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

fn apply_layer(root: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
	// No entry of this layer exists yet: whiteouts remove only lower layers'.
	apply_whiteouts(root, bytes)?;
	let mut archive = tar::Archive::new(Cursor::new(bytes));
	let entries =
		archive.entries().map_err(|_| invalid("invalid OCI layer tar"))?;
	let mut seen = HashSet::new();
	let mut directories = Vec::new();
	for (index, entry) in entries.enumerate() {
		if index >= MAX_LAYER_ENTRIES {
			return Err(invalid("OCI layer entry-count limit exceeded"));
		}
		let mut entry =
			entry.map_err(|_| invalid("invalid OCI layer entry"))?;
		let relative = layer_path(&entry)?;
		if !seen.insert(relative.clone()) {
			return Err(invalid("duplicate path in OCI layer"));
		}
		if whiteout_name(&relative).is_some() {
			continue;
		}
		let kind = entry.header().entry_type();
		if relative.as_os_str().is_empty() {
			// The layer's root directory entry, `.` or `./`, carries the
			// root's own metadata.
			if !kind.is_dir() {
				return Err(invalid("OCI layer root entry is not a directory"));
			}
			directories.push(entry_metadata(
				&mut entry,
				root.to_path_buf(),
				false,
			)?);
			continue;
		}
		ensure_safe_parents(root, &relative)?;
		let destination = root.join(&relative);
		let metadata =
			entry_metadata(&mut entry, destination.clone(), kind.is_symlink())?;
		if kind.is_dir() {
			ensure_layer_directory(&destination)?;
			directories.push(metadata);
		} else if kind.is_file() {
			remove_path_if_present(&destination)?;
			let mut file = OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&destination)
				.map_err(|_| invalid("failed to create layer file"))?;
			std::io::copy(&mut entry, &mut file)
				.map_err(|_| invalid("failed to write layer file"))?;
			apply_metadata(&metadata)?;
		} else if kind.is_symlink() {
			let target = entry
				.link_name()
				.map_err(|_| invalid("invalid layer symlink"))?
				.ok_or_else(|| invalid("layer symlink has no target"))?;
			validate_symlink_target(&relative, &target)?;
			remove_path_if_present(&destination)?;
			std::os::unix::fs::symlink(&target, &destination)
				.map_err(|_| invalid("failed to create layer symlink"))?;
			apply_metadata(&metadata)?;
		} else if kind.is_hard_link() {
			let target = entry
				.link_name()
				.map_err(|_| invalid("invalid layer hard link"))?
				.ok_or_else(|| invalid("layer hard link has no target"))?;
			let target = normalized_link_target(&relative, &target, false)?;
			ensure_safe_parents(root, &target)?;
			let source = root.join(target);
			let found = fs::symlink_metadata(&source).map_err(|_| {
				invalid("layer hard-link target does not exist")
			})?;
			if found.is_dir() || found.file_type().is_symlink() {
				return Err(invalid("invalid layer hard-link target"));
			}
			remove_path_if_present(&destination)?;
			fs::hard_link(source, &destination)
				.map_err(|_| invalid("failed to create layer hard link"))?;
			apply_metadata(&metadata)?;
		} else if kind.is_fifo() {
			remove_path_if_present(&destination)?;
			mkfifo(&destination, metadata.mode)?;
			apply_metadata(&metadata)?;
		} else {
			return Err(invalid("unsupported OCI layer entry type"));
		}
	}
	// Directory metadata is applied last so child creation cannot alter it or
	// be blocked by its final permissions. Children precede parents.
	directories.sort_by_cached_key(|metadata| {
		std::cmp::Reverse(metadata.path.components().count())
	});
	for metadata in directories {
		apply_metadata(&metadata)?;
	}
	Ok(())
}

fn apply_whiteouts(root: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
	let mut archive = tar::Archive::new(Cursor::new(bytes));
	let entries = archive
		.entries_with_seek()
		.map_err(|_| invalid("invalid OCI layer tar"))?;
	for entry in entries {
		let entry = entry.map_err(|_| invalid("invalid OCI layer entry"))?;
		let relative = layer_path(&entry)?;
		if let Some(whiteout) = whiteout_name(&relative) {
			apply_whiteout(root, &relative, whiteout, &entry)?;
		}
	}
	Ok(())
}

fn ensure_layer_directory(destination: &Path) -> Result<(), ProtocolError> {
	match fs::symlink_metadata(destination) {
		Ok(found) if found.is_dir() => return Ok(()),
		Ok(_) => remove_path(destination)?,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
		Err(_) => return Err(invalid("failed to inspect layer directory")),
	}
	fs::create_dir(destination)
		.map_err(|_| invalid("failed to create layer directory"))
}

fn layer_path<R: Read>(
	entry: &tar::Entry<'_, R>,
) -> Result<PathBuf, ProtocolError> {
	normalized_relative(
		&entry.path().map_err(|_| invalid("invalid OCI layer path"))?,
	)
}

fn normalized_relative(path: &Path) -> Result<PathBuf, ProtocolError> {
	if path.as_os_str().is_empty()
		|| path.is_absolute()
		|| path.as_os_str().len() > MAX_LAYER_PATH_BYTES
	{
		return Err(invalid("OCI layer path is unsafe"));
	}
	let mut output = PathBuf::new();
	for component in path.components() {
		match component {
			Component::CurDir => {}
			Component::Normal(part) => output.push(part),
			_ => return Err(invalid("OCI layer path is not normalized")),
		}
	}
	Ok(output)
}

fn normalized_link_target(
	entry: &Path,
	target: &Path,
	relative_to_parent: bool,
) -> Result<PathBuf, ProtocolError> {
	if target.as_os_str().is_empty()
		|| target.as_os_str().len() > MAX_LAYER_PATH_BYTES
	{
		return Err(invalid("OCI layer link target is unsafe"));
	}
	let mut parts: Vec<std::ffi::OsString> = if target.is_absolute() {
		Vec::new()
	} else if relative_to_parent {
		entry
			.parent()
			.into_iter()
			.flat_map(Path::components)
			.filter_map(|part| match part {
				Component::Normal(value) => Some(value.to_os_string()),
				_ => None,
			})
			.collect()
	} else {
		Vec::new()
	};
	for component in target.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::Normal(part) => parts.push(part.to_os_string()),
			Component::ParentDir => {
				if parts.pop().is_none() {
					return Err(invalid("OCI layer link escapes rootfs"));
				}
			}
			Component::Prefix(_) => {
				return Err(invalid("OCI layer link target is unsafe"));
			}
		}
	}
	Ok(parts.into_iter().collect())
}

fn validate_symlink_target(
	entry: &Path,
	target: &Path,
) -> Result<(), ProtocolError> {
	normalized_link_target(entry, target, true).map(|_| ())
}

fn ensure_safe_parents(
	root: &Path,
	relative: &Path,
) -> Result<(), ProtocolError> {
	let mut current = root.to_path_buf();
	if let Some(parent) = relative.parent() {
		for component in parent.components() {
			let Component::Normal(part) = component else {
				return Err(invalid("invalid OCI layer parent path"));
			};
			current.push(part);
			match fs::symlink_metadata(&current) {
				Ok(metadata) if metadata.is_dir() => {}
				Ok(_) => {
					return Err(invalid("OCI layer parent is not a directory"));
				}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
					fs::create_dir(&current).map_err(|_| {
						invalid("failed to create OCI layer parent")
					})?;
				}
				Err(_) => {
					return Err(invalid("failed to inspect OCI layer parent"));
				}
			}
		}
	}
	Ok(())
}

fn whiteout_name(relative: &Path) -> Option<&str> {
	relative.file_name()?.to_str()?.strip_prefix(WHITEOUT_PREFIX)
}

/// Remove what one whiteout marker hides in the lower layers. A marker must be
/// an empty regular file. `.wh..wh..opq` hides every lower entry of its
/// directory; `.wh.<name>` hides the lower entry `<name>`, which must be one
/// ordinary basename. Lookup follows no symlink and creates nothing: a lower
/// path that is absent, or not a directory, has nothing to remove.
fn apply_whiteout<R: Read>(
	root: &Path,
	relative: &Path,
	whiteout: &str,
	entry: &tar::Entry<'_, R>,
) -> Result<(), ProtocolError> {
	if !entry.header().entry_type().is_file() || entry.size() != 0 {
		return Err(invalid("OCI whiteout is not an empty regular file"));
	}
	let opaque =
		relative.file_name().is_some_and(|name| name == OPAQUE_WHITEOUT);
	if !opaque
		&& (whiteout.is_empty()
			|| whiteout == "."
			|| whiteout == ".."
			|| whiteout.starts_with(WHITEOUT_PREFIX))
	{
		return Err(invalid("invalid OCI whiteout"));
	}
	let Some(directory) = lower_directory(
		root,
		relative.parent().unwrap_or_else(|| Path::new("")),
	)?
	else {
		return Ok(());
	};
	if opaque {
		for child in fs::read_dir(&directory)
			.map_err(|_| invalid("failed to apply opaque whiteout"))?
		{
			remove_path(
				&child.map_err(|_| invalid("invalid whiteout target"))?.path(),
			)?;
		}
		Ok(())
	} else {
		remove_path_if_present(&directory.join(whiteout))
	}
}

fn lower_directory(
	root: &Path,
	relative: &Path,
) -> Result<Option<PathBuf>, ProtocolError> {
	let mut current = root.to_path_buf();
	for component in relative.components() {
		let Component::Normal(part) = component else {
			return Err(invalid("invalid OCI whiteout path"));
		};
		current.push(part);
		match fs::symlink_metadata(&current) {
			Ok(metadata) if metadata.is_dir() => {}
			Ok(_) => return Ok(None),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				return Ok(None);
			}
			Err(_) => {
				return Err(invalid("failed to inspect OCI whiteout path"));
			}
		}
	}
	Ok(Some(current))
}

fn remove_path_if_present(path: &Path) -> Result<(), ProtocolError> {
	match fs::symlink_metadata(path) {
		Ok(_) => remove_path(path),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(_) => Err(invalid("failed to inspect OCI layer destination")),
	}
}

fn remove_path(path: &Path) -> Result<(), ProtocolError> {
	let metadata = fs::symlink_metadata(path)
		.map_err(|_| invalid("failed to inspect OCI layer destination"))?;
	if metadata.is_dir() {
		fs::remove_dir_all(path)
	} else {
		fs::remove_file(path)
	}
	.map_err(|_| invalid("failed to replace OCI layer path"))
}

fn entry_metadata<R: Read>(
	entry: &mut tar::Entry<'_, R>,
	path: PathBuf,
	symlink: bool,
) -> Result<Metadata, ProtocolError> {
	let header = entry.header();
	let mode = header.mode().map_err(|_| invalid("invalid layer mode"))?;
	let uid =
		u32::try_from(header.uid().map_err(|_| invalid("invalid layer uid"))?)
			.map_err(|_| invalid("layer uid exceeds Linux range"))?;
	let gid =
		u32::try_from(header.gid().map_err(|_| invalid("invalid layer gid"))?)
			.map_err(|_| invalid("layer gid exceeds Linux range"))?;
	let mut mtime = i64::try_from(
		header.mtime().map_err(|_| invalid("invalid layer mtime"))?,
	)
	.map_err(|_| invalid("layer mtime exceeds Linux range"))?;
	let mut mtime_nsec = 0;
	let mut xattrs = Vec::new();
	if let Some(extensions) = entry
		.pax_extensions()
		.map_err(|_| invalid("invalid layer PAX metadata"))?
	{
		for extension in extensions {
			let extension =
				extension.map_err(|_| invalid("invalid layer PAX record"))?;
			if extension.key_bytes() == b"mtime" {
				(mtime, mtime_nsec) = pax_time(extension.value_bytes())?;
				continue;
			}
			let Some(name) =
				extension.key_bytes().strip_prefix(b"SCHILY.xattr.")
			else {
				continue;
			};
			// Labels of the environment that built the image, which the
			// enclave does not use.
			if IGNORED_XATTRS.contains(&name) {
				continue;
			}
			validate_xattr(name)?;
			xattrs.push((
				CString::new(name)
					.map_err(|_| invalid("invalid layer xattr name"))?,
				extension.value_bytes().to_vec(),
			));
		}
	}
	Ok(Metadata { path, mode, uid, gid, mtime, mtime_nsec, xattrs, symlink })
}

const IGNORED_XATTRS: [&[u8]; 3] =
	[b"security.selinux", b"security.ima", b"security.evm"];

fn pax_time(value: &[u8]) -> Result<(i64, i64), ProtocolError> {
	let unrepresentable = || invalid("unrepresentable layer PAX mtime");
	let text = std::str::from_utf8(value).map_err(|_| unrepresentable())?;
	let (negative, text) =
		text.strip_prefix('-').map_or((false, text), |rest| (true, rest));
	let (seconds, fraction) = text.split_once('.').unwrap_or((text, ""));
	if !decimal(seconds) || !fraction.bytes().all(|byte| byte.is_ascii_digit())
	{
		return Err(unrepresentable());
	}
	let seconds: i64 = seconds.parse().map_err(|_| unrepresentable())?;
	let nanos = fraction
		.bytes()
		.chain(std::iter::repeat(b'0'))
		.take(9)
		.fold(0_i64, |nanos, digit| nanos * 10 + i64::from(digit - b'0'));
	Ok(if !negative {
		(seconds, nanos)
	} else if nanos == 0 {
		(-seconds, 0)
	} else {
		(-seconds - 1, 1_000_000_000 - nanos)
	})
}

fn validate_xattr(name: &[u8]) -> Result<(), ProtocolError> {
	let allowed = name.starts_with(b"user.")
		|| name == b"security.capability"
		|| name == b"system.posix_acl_access"
		|| name == b"system.posix_acl_default";
	if !allowed
		&& (name.starts_with(b"security.") || name.starts_with(b"trusted."))
	{
		return Err(invalid("forbidden OCI layer extended attribute"));
	}
	if !allowed {
		return Err(invalid("unsupported OCI layer extended attribute"));
	}
	Ok(())
}

#[allow(unsafe_code)]
fn apply_metadata(metadata: &Metadata) -> Result<(), ProtocolError> {
	let path = CString::new(metadata.path.as_os_str().as_bytes())
		.map_err(|_| invalid("invalid rootfs metadata path"))?;
	// SAFETY: `path` is NUL-terminated and points to the newly-created rootfs
	// entry. lchown and AT_SYMLINK_NOFOLLOW deliberately do not follow links.
	if unsafe { libc::lchown(path.as_ptr(), metadata.uid, metadata.gid) } != 0 {
		return Err(invalid("failed to preserve OCI layer ownership"));
	}
	if !metadata.symlink {
		fs::set_permissions(
			&metadata.path,
			fs::Permissions::from_mode(metadata.mode),
		)
		.map_err(|_| invalid("failed to preserve OCI layer mode"))?;
	}
	for (name, value) in &metadata.xattrs {
		// SAFETY: both pointers remain valid for the duration of lsetxattr.
		if unsafe {
			libc::lsetxattr(
				path.as_ptr(),
				name.as_ptr(),
				value.as_ptr().cast(),
				value.len(),
				0,
			)
		} != 0
		{
			return Err(invalid(
				"failed to preserve OCI layer extended attribute",
			));
		}
	}
	let time =
		libc::timespec { tv_sec: metadata.mtime, tv_nsec: metadata.mtime_nsec };
	let times = [time, time];
	// SAFETY: arguments are valid and AT_SYMLINK_NOFOLLOW prevents escape.
	if unsafe {
		libc::utimensat(
			libc::AT_FDCWD,
			path.as_ptr(),
			times.as_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} != 0
	{
		return Err(invalid("failed to preserve OCI layer modification time"));
	}
	Ok(())
}

#[allow(unsafe_code)]
fn mkfifo(path: &Path, mode: u32) -> Result<(), ProtocolError> {
	let path = CString::new(path.as_os_str().as_bytes())
		.map_err(|_| invalid("invalid FIFO path"))?;
	// SAFETY: path is a valid C string below the fresh rootfs.
	if unsafe { libc::mkfifo(path.as_ptr(), mode) } == 0 {
		Ok(())
	} else {
		Err(invalid("failed to create OCI layer FIFO"))
	}
}

fn resolve_process(
	rootfs: &Path,
	image: &VerifiedProcess,
) -> Result<RuntimeProcess, ProtocolError> {
	let mut args = image.entrypoint.clone();
	args.extend(image.cmd.iter().cloned());
	if args.is_empty() || args.iter().any(|arg| arg.contains('\0')) {
		return Err(invalid("OCI process arguments are empty or contain NUL"));
	}
	let env = normalize_env(&image.env)?;
	let cwd = normalized_container_path(&image.working_dir)?;
	let cwd_host = resolve_rootfs_path(rootfs, &cwd)?;
	if !fs::symlink_metadata(&cwd_host).is_ok_and(|metadata| metadata.is_dir())
	{
		return Err(invalid("OCI working directory does not exist"));
	}
	let executable = resolve_executable(rootfs, &cwd, &args[0], &env)?;
	args[0] = executable;
	let identity = resolve_identity(rootfs, &image.user)?;
	let stop_signal = parse_signal(image.stop_signal.as_deref())?;
	Ok(RuntimeProcess { args, env, cwd, identity, stop_signal })
}

fn normalize_env(entries: &[String]) -> Result<Vec<String>, ProtocolError> {
	let mut order = Vec::new();
	let mut values = HashMap::new();
	for entry in entries {
		let (name, value) = entry.split_once('=').ok_or_else(|| {
			invalid("OCI environment entry has no equals sign")
		})?;
		if name.is_empty() || name.contains('\0') || value.contains('\0') {
			return Err(invalid("invalid OCI environment entry"));
		}
		if !values.contains_key(name) {
			order.push(name.to_owned());
		}
		values.insert(name.to_owned(), value.to_owned());
	}
	if !values.contains_key("PATH") {
		order.push("PATH".into());
		values.insert("PATH".into(), DEFAULT_PATH.into());
	}
	Ok(order
		.into_iter()
		.map(|name| format!("{name}={}", values[&name]))
		.collect())
}

fn resolve_executable(
	rootfs: &Path,
	cwd: &Path,
	executable: &str,
	env: &[String],
) -> Result<String, ProtocolError> {
	let candidates: Vec<PathBuf> = if executable.contains('/') {
		vec![normalized_container_path(
			&cwd.join(executable).to_string_lossy(),
		)?]
	} else {
		let path = env
			.iter()
			.find_map(|entry| entry.strip_prefix("PATH="))
			.expect("PATH is normalized");
		path.split(':')
			.map(|directory| {
				let path = Path::new(directory).join(executable);
				if path.is_absolute() {
					normalized_container_path(&path.to_string_lossy())
				} else {
					normalized_container_path(&cwd.join(path).to_string_lossy())
				}
			})
			.collect::<Result<_, _>>()?
	};
	let search = !executable.contains('/');
	for candidate in candidates {
		let host = match resolve_rootfs_path(rootfs, &candidate) {
			Ok(host) => host,
			Err(_) if search => continue,
			Err(error) => return Err(error),
		};
		if fs::symlink_metadata(&host).is_ok_and(|metadata| {
			metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
		}) {
			return Ok(candidate.to_string_lossy().into_owned());
		}
	}
	Err(invalid("OCI executable was not found in rootfs"))
}

/// Resolve container symlinks without ever allowing an absolute link to be
/// interpreted relative to the parent QOS root.
fn resolve_rootfs_path(
	rootfs: &Path,
	container_path: &Path,
) -> Result<PathBuf, ProtocolError> {
	find_rootfs_path(rootfs, container_path)?
		.ok_or_else(|| invalid("OCI process path does not exist"))
}

fn find_rootfs_path(
	rootfs: &Path,
	container_path: &Path,
) -> Result<Option<PathBuf>, ProtocolError> {
	let normalized =
		normalized_container_path(&container_path.to_string_lossy())?;
	let mut pending: VecDeque<_> = normalized
		.strip_prefix("/")
		.expect("normalized path is absolute")
		.components()
		.filter_map(|component| match component {
			Component::Normal(part) => Some(part.to_os_string()),
			_ => None,
		})
		.collect();
	let mut resolved = PathBuf::new();
	let mut links = 0;
	while let Some(part) = pending.pop_front() {
		let candidate = rootfs.join(&resolved).join(&part);
		let metadata = match fs::symlink_metadata(&candidate) {
			Ok(metadata) => metadata,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				return Ok(None);
			}
			Err(_) => {
				return Err(invalid("failed to inspect OCI process path"));
			}
		};
		if metadata.file_type().is_symlink() {
			links += 1;
			if links > 40 {
				return Err(invalid("too many symlinks in OCI process path"));
			}
			let target = fs::read_link(&candidate)
				.map_err(|_| invalid("failed to read OCI process symlink"))?;
			let target =
				normalized_link_target(&resolved.join(&part), &target, true)?;
			let mut replacement: VecDeque<_> = target
				.components()
				.filter_map(|component| match component {
					Component::Normal(part) => Some(part.to_os_string()),
					_ => None,
				})
				.collect();
			replacement.append(&mut pending);
			pending = replacement;
			resolved.clear();
		} else {
			resolved.push(part);
		}
	}
	Ok(Some(rootfs.join(resolved)))
}

fn normalized_container_path(value: &str) -> Result<PathBuf, ProtocolError> {
	let path = Path::new(value);
	if !path.is_absolute() || value.contains('\0') {
		return Err(invalid("OCI process path is not absolute"));
	}
	let mut output = PathBuf::from("/");
	for component in path.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::Normal(part) => output.push(part),
			_ => return Err(invalid("OCI process path escapes rootfs")),
		}
	}
	Ok(output)
}

struct Passwd {
	name: String,
	uid: u32,
	gid: u32,
}

struct Group {
	name: String,
	gid: u32,
	members: Vec<String>,
}

fn resolve_identity(
	rootfs: &Path,
	value: &str,
) -> Result<ProcessIdentity, ProtocolError> {
	if value.is_empty() {
		return Ok(ProcessIdentity {
			uid: 0,
			gid: 0,
			additional_gids: Vec::new(),
		});
	}
	let passwd = parse_passwd(rootfs)?;
	let groups = parse_groups(rootfs)?;
	let (user, group) =
		value.split_once(':').map_or((value, None), |(u, g)| (u, Some(g)));
	if user.is_empty() || group.is_some_and(str::is_empty) {
		return Err(invalid("invalid OCI user expression"));
	}
	let user_record = if decimal(user) {
		None
	} else {
		Some(
			passwd
				.iter()
				.find(|entry| entry.name == user)
				.ok_or_else(|| invalid("OCI user was not found"))?,
		)
	};
	let uid = if decimal(user) {
		parse_id(user)?
	} else {
		user_record.expect("resolved name").uid
	};
	let gid = match group {
		Some(group) if decimal(group) => parse_id(group)?,
		Some(group) => groups
			.iter()
			.find(|entry| entry.name == group)
			.map(|entry| entry.gid)
			.ok_or_else(|| invalid("OCI group was not found"))?,
		None => user_record
			.or_else(|| passwd.iter().find(|entry| entry.uid == uid))
			.map(|entry| entry.gid)
			.ok_or_else(|| invalid("OCI numeric user has no passwd entry"))?,
	};
	let mut additional_gids = if group.is_none() {
		let name = user_record
			.or_else(|| passwd.iter().find(|entry| entry.uid == uid))
			.map(|entry| entry.name.as_str())
			.ok_or_else(|| invalid("OCI user has no passwd entry"))?;
		groups
			.iter()
			.filter(|entry| {
				entry.gid != gid
					&& entry.members.iter().any(|member| member == name)
			})
			.map(|entry| entry.gid)
			.collect()
	} else {
		Vec::new()
	};
	additional_gids.sort_unstable();
	additional_gids.dedup();
	Ok(ProcessIdentity { uid, gid, additional_gids })
}

fn read_identity_file(
	rootfs: &Path,
	path: &str,
) -> Result<String, ProtocolError> {
	match find_rootfs_path(rootfs, Path::new(path))? {
		None => Ok(String::new()),
		Some(host) => fs::read_to_string(host)
			.map_err(|_| invalid(format!("failed to read image {path}"))),
	}
}

fn parse_passwd(rootfs: &Path) -> Result<Vec<Passwd>, ProtocolError> {
	let text = read_identity_file(rootfs, "/etc/passwd")?;
	text.lines()
		.map(|line| {
			let fields: Vec<_> = line.split(':').collect();
			if fields.len() < 4 || fields[0].is_empty() {
				return Err(invalid("invalid image /etc/passwd"));
			}
			Ok(Passwd {
				name: fields[0].into(),
				uid: parse_id(fields[2])?,
				gid: parse_id(fields[3])?,
			})
		})
		.collect()
}

fn parse_groups(rootfs: &Path) -> Result<Vec<Group>, ProtocolError> {
	let text = read_identity_file(rootfs, "/etc/group")?;
	text.lines()
		.map(|line| {
			let fields: Vec<_> = line.split(':').collect();
			if fields.len() < 4 || fields[0].is_empty() {
				return Err(invalid("invalid image /etc/group"));
			}
			Ok(Group {
				name: fields[0].into(),
				gid: parse_id(fields[2])?,
				members: fields[3]
					.split(',')
					.filter(|v| !v.is_empty())
					.map(str::to_owned)
					.collect(),
			})
		})
		.collect()
}

fn decimal(value: &str) -> bool {
	!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_id(value: &str) -> Result<u32, ProtocolError> {
	if !decimal(value) {
		return Err(invalid("invalid numeric OCI user or group"));
	}
	value.parse().map_err(|_| invalid("OCI user or group exceeds Linux range"))
}

fn parse_signal(value: Option<&str>) -> Result<i32, ProtocolError> {
	let Some(value) = value.filter(|value| !value.is_empty()) else {
		return Ok(libc::SIGTERM);
	};
	let number = if decimal(value) {
		value.parse::<i32>().map_err(|_| invalid("invalid OCI stop signal"))?
	} else {
		match value
			.strip_prefix("SIG")
			.unwrap_or(value)
			.to_ascii_uppercase()
			.as_str()
		{
			"HUP" => libc::SIGHUP,
			"INT" => libc::SIGINT,
			"QUIT" => libc::SIGQUIT,
			"ILL" => libc::SIGILL,
			"TRAP" => libc::SIGTRAP,
			"ABRT" | "IOT" => libc::SIGABRT,
			"BUS" => libc::SIGBUS,
			"FPE" => libc::SIGFPE,
			"KILL" => libc::SIGKILL,
			"SEGV" => libc::SIGSEGV,
			"STKFLT" => libc::SIGSTKFLT,
			"TERM" => libc::SIGTERM,
			"USR1" => libc::SIGUSR1,
			"USR2" => libc::SIGUSR2,
			"CHLD" => libc::SIGCHLD,
			"CONT" => libc::SIGCONT,
			"STOP" => libc::SIGSTOP,
			"TSTP" => libc::SIGTSTP,
			"TTIN" => libc::SIGTTIN,
			"TTOU" => libc::SIGTTOU,
			"PIPE" => libc::SIGPIPE,
			"ALRM" => libc::SIGALRM,
			"XCPU" => libc::SIGXCPU,
			"XFSZ" => libc::SIGXFSZ,
			"VTALRM" => libc::SIGVTALRM,
			"PROF" => libc::SIGPROF,
			"WINCH" => libc::SIGWINCH,
			"IO" | "POLL" => libc::SIGIO,
			"PWR" => libc::SIGPWR,
			"SYS" | "UNUSED" => libc::SIGSYS,
			_ => return Err(invalid("invalid OCI stop signal")),
		}
	};
	if !(1..=64).contains(&number) {
		return Err(invalid("invalid OCI stop signal"));
	}
	Ok(number)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn rootfs() -> PathBuf {
		let root = std::env::temp_dir().join(format!(
			"qos-oci-bundle-path-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		drop(fs::remove_dir_all(&root));
		fs::create_dir_all(root.join("usr/local/sbin")).unwrap();
		fs::create_dir_all(root.join("usr/local/bin")).unwrap();
		let script = root.join("usr/local/bin/docker-entrypoint.sh");
		fs::write(&script, "#!/bin/sh\n").unwrap();
		fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
			.unwrap();
		root
	}

	fn scratch(name: &str) -> PathBuf {
		let root = std::env::temp_dir()
			.join(format!("qos-oci-bundle-{name}-{}", std::process::id()));
		drop(fs::remove_dir_all(&root));
		fs::create_dir_all(&root).unwrap();
		root
	}

	enum Entry<'a> {
		File(&'a str, &'a [u8]),
		Dir(&'a str),
		Pax(Vec<(&'a str, &'a [u8])>),
	}

	/// One PAX record, `<length> <key>=<value>\n`, whose length counts
	/// itself.
	fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
		let rest = key.len() + value.len() + 3;
		let mut length = rest + rest.to_string().len();
		if length.to_string().len() != rest.to_string().len() {
			length += 1;
		}
		let mut record = format!("{length} {key}=").into_bytes();
		record.extend_from_slice(value);
		record.push(b'\n');
		assert_eq!(record.len(), length);
		record
	}

	fn layer(entries: &[Entry<'_>]) -> Vec<u8> {
		let mut builder = tar::Builder::new(Vec::new());
		for entry in entries {
			let mut header = tar::Header::new_ustar();
			let (name, data): (&str, Vec<u8>) = match entry {
				Entry::File(path, data) => {
					header.set_entry_type(tar::EntryType::Regular);
					header.set_mode(0o644);
					(path, data.to_vec())
				}
				Entry::Dir(path) => {
					header.set_entry_type(tar::EntryType::Directory);
					header.set_mode(0o750);
					(path, Vec::new())
				}
				Entry::Pax(records) => {
					header.set_entry_type(tar::EntryType::XHeader);
					let data = records
						.iter()
						.flat_map(|(key, value)| pax_record(key, value))
						.collect();
					("PaxHeaders/entry", data)
				}
			};
			header.as_ustar_mut().unwrap().name[..name.len()]
				.copy_from_slice(name.as_bytes());
			header.set_uid(0);
			header.set_gid(0);
			header.set_mtime(0);
			header.set_size(data.len() as u64);
			header.set_cksum();
			builder.append(&header, &data[..]).unwrap();
		}
		builder.into_inner().unwrap()
	}

	#[test]
	fn whiteouts_remove_only_lower_layer_entries() {
		let root = scratch("whiteout-order");
		apply_layer(
			&root,
			&layer(&[
				Entry::File("a/lower", b"lower"),
				Entry::File("b/x", b"old"),
			]),
		)
		.unwrap();
		apply_layer(
			&root,
			&layer(&[
				Entry::File("a/new", b"new"),
				Entry::File("a/.wh..wh..opq", b""),
				Entry::File("b/x", b"new"),
				Entry::File("b/.wh.x", b""),
			]),
		)
		.unwrap();
		assert!(!root.join("a/lower").exists());
		assert_eq!(fs::read(root.join("a/new")).unwrap(), b"new");
		assert_eq!(fs::read(root.join("b/x")).unwrap(), b"new");
		assert!(!root.join("a/.wh..wh..opq").exists());
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn whiteouts_cannot_name_the_directory_or_its_parent() {
		let root = scratch("whiteout-dots");
		let rootfs = root.join("rootfs");
		fs::create_dir(&rootfs).unwrap();
		fs::write(root.join("outside"), b"keep").unwrap();
		for marker in [".wh...", ".wh..", ".wh."] {
			assert!(
				apply_layer(&rootfs, &layer(&[Entry::File(marker, b"")]))
					.is_err(),
				"{marker} must be rejected"
			);
		}
		assert!(
			apply_layer(&rootfs, &layer(&[Entry::File("a/.wh.x", b"data")]))
				.is_err(),
			"a whiteout must be empty"
		);
		assert_eq!(fs::read(root.join("outside")).unwrap(), b"keep");
		assert!(rootfs.exists());
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn whiteouts_do_not_follow_lower_symlinks() {
		let root = scratch("whiteout-symlink");
		let rootfs = root.join("rootfs");
		fs::create_dir_all(root.join("elsewhere")).unwrap();
		fs::write(root.join("elsewhere/x"), b"keep").unwrap();
		fs::create_dir(&rootfs).unwrap();
		std::os::unix::fs::symlink(root.join("elsewhere"), rootfs.join("a"))
			.unwrap();
		apply_layer(&rootfs, &layer(&[Entry::File("a/.wh.x", b"")])).unwrap();
		apply_layer(&rootfs, &layer(&[Entry::File("a/.wh..wh..opq", b"")]))
			.unwrap();
		assert_eq!(fs::read(root.join("elsewhere/x")).unwrap(), b"keep");
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn layer_paths_may_start_with_the_current_directory() {
		let root = scratch("current-dir");
		apply_layer(
			&root,
			&layer(&[
				Entry::Dir("./"),
				Entry::Dir("./etc/"),
				Entry::File("./etc/app.conf", b"conf"),
			]),
		)
		.unwrap();
		assert_eq!(fs::read(root.join("etc/app.conf")).unwrap(), b"conf");
		assert_eq!(
			fs::metadata(&root).unwrap().permissions().mode() & 0o777,
			0o750
		);
		assert!(
			apply_layer(
				&root,
				&layer(&[Entry::File("x", b"1"), Entry::File("./x", b"2")])
			)
			.is_err(),
			"`x` and `./x` are the same path"
		);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn build_environment_labels_are_ignored_and_pax_mtime_is_kept() {
		let root = scratch("pax");
		apply_layer(
			&root,
			&layer(&[
				Entry::Pax(vec![
					("SCHILY.xattr.security.selinux", b"system_u:object_r:x"),
					("mtime", b"1700000000.25"),
				]),
				Entry::File("labelled", b"data"),
			]),
		)
		.unwrap();
		let metadata = fs::symlink_metadata(root.join("labelled")).unwrap();
		assert_eq!(
			std::os::unix::fs::MetadataExt::mtime(&metadata),
			1_700_000_000
		);
		assert_eq!(
			std::os::unix::fs::MetadataExt::mtime_nsec(&metadata),
			250_000_000
		);
		assert!(
			apply_layer(
				&root,
				&layer(&[
					Entry::Pax(vec![("SCHILY.xattr.trusted.x", b"1")]),
					Entry::File("trusted", b"data"),
				])
			)
			.is_err(),
			"other security and trusted attributes stay forbidden"
		);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn pax_times_keep_nanoseconds() {
		assert_eq!(pax_time(b"12").unwrap(), (12, 0));
		assert_eq!(pax_time(b"12.5").unwrap(), (12, 500_000_000));
		assert_eq!(pax_time(b"12.1234567891").unwrap(), (12, 123_456_789));
		assert_eq!(pax_time(b"-1.25").unwrap(), (-2, 750_000_000));
		for bad in [&b""[..], b"x", b"1.x", b"1e3", b"--1", b"."] {
			assert!(pax_time(bad).is_err(), "{bad:?}");
		}
	}

	#[test]
	fn identity_files_resolve_through_image_symlinks() {
		let root = scratch("identity");
		fs::create_dir_all(root.join("etc")).unwrap();
		fs::create_dir_all(root.join("usr/share")).unwrap();
		fs::write(
			root.join("usr/share/passwd"),
			"app:x:1000:1000::/:/bin/sh\n",
		)
		.unwrap();
		fs::write(root.join("usr/share/group"), "app:x:1000:\nextra:x:7:app\n")
			.unwrap();
		std::os::unix::fs::symlink(
			"/usr/share/passwd",
			root.join("etc/passwd"),
		)
		.unwrap();
		std::os::unix::fs::symlink(
			"../usr/share/group",
			root.join("etc/group"),
		)
		.unwrap();
		assert_eq!(
			resolve_identity(&root, "app").unwrap(),
			ProcessIdentity { uid: 1000, gid: 1000, additional_gids: vec![7] }
		);
		fs::remove_dir_all(root.join("usr/share")).unwrap();
		assert!(
			resolve_identity(&root, "app").is_err(),
			"a dangling link has no records"
		);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn relative_executables_resolve_against_the_working_directory() {
		let root = rootfs();
		let env = vec![format!("PATH={DEFAULT_PATH}")];
		assert_eq!(
			resolve_executable(
				&root,
				Path::new("/usr/local"),
				"./bin/docker-entrypoint.sh",
				&env
			)
			.unwrap(),
			"/usr/local/bin/docker-entrypoint.sh"
		);
		assert_eq!(
			resolve_executable(
				&root,
				Path::new("/usr/local"),
				"bin/docker-entrypoint.sh",
				&env
			)
			.unwrap(),
			"/usr/local/bin/docker-entrypoint.sh"
		);
		assert!(
			resolve_executable(&root, Path::new("/"), "../x", &env).is_err()
		);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn path_search_skips_entries_without_the_executable() {
		let root = rootfs();
		let env = vec![format!("PATH={DEFAULT_PATH}")];
		let cwd = Path::new("/");
		assert_eq!(
			resolve_executable(&root, cwd, "docker-entrypoint.sh", &env)
				.unwrap(),
			"/usr/local/bin/docker-entrypoint.sh"
		);
		assert!(resolve_executable(&root, cwd, "missing", &env).is_err());
		assert!(
			resolve_executable(&root, cwd, "/usr/local/sbin/x", &env).is_err()
		);
		assert_eq!(
			resolve_executable(
				&root,
				cwd,
				"/usr/local/bin/docker-entrypoint.sh",
				&env
			)
			.unwrap(),
			"/usr/local/bin/docker-entrypoint.sh"
		);
		fs::remove_dir_all(root).unwrap();
	}
}
