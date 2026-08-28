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

/// Prepare a regular-file bind-mount target without following image symlinks.
///
/// # Errors
///
/// Returns an error when the target escapes the rootfs or is not regular.
pub fn prepare_file_target(
	rootfs: &Path,
	container_path: &Path,
) -> Result<(), ProtocolError> {
	let relative = container_relative(container_path)?;
	ensure_safe_parents(rootfs, &relative)?;
	let target = rootfs.join(relative);
	match fs::symlink_metadata(&target) {
		Ok(metadata) if metadata.is_file() => Ok(()),
		Ok(_) => Err(invalid("OCI file target is not a regular file")),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(target)
				.map(|_| ())
				.map_err(|_| invalid("failed to create OCI file target"))
		}
		Err(_) => Err(invalid("failed to inspect OCI file target")),
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
	xattrs: Vec<(CString, Vec<u8>)>,
	symlink: bool,
}

fn apply_layer(root: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
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
		let relative = normalized_relative(
			&entry.path().map_err(|_| invalid("invalid OCI layer path"))?,
		)?;
		if !seen.insert(relative.clone()) {
			return Err(invalid("duplicate path in OCI layer"));
		}
		if apply_whiteout(root, &relative)? {
			continue;
		}
		ensure_safe_parents(root, &relative)?;
		let destination = root.join(&relative);
		let kind = entry.header().entry_type();
		let metadata =
			entry_metadata(&mut entry, destination.clone(), kind.is_symlink())?;
		if kind.is_dir() {
			match fs::symlink_metadata(&destination) {
				Ok(found) if found.is_dir() => {}
				Ok(_) => {
					remove_path(&destination)?;
					fs::create_dir(&destination).map_err(|_| {
						invalid("failed to create layer directory")
					})?;
				}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
					fs::create_dir(&destination).map_err(|_| {
						invalid("failed to create layer directory")
					})?;
				}
				Err(_) => {
					return Err(invalid("failed to inspect layer directory"));
				}
			}
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
	directories.sort_by_key(|metadata| {
		std::cmp::Reverse(metadata.path.components().count())
	});
	for metadata in directories {
		apply_metadata(&metadata)?;
	}
	Ok(())
}

fn normalized_relative(path: &Path) -> Result<PathBuf, ProtocolError> {
	if path.is_absolute() || path.as_os_str().len() > MAX_LAYER_PATH_BYTES {
		return Err(invalid("OCI layer path is unsafe"));
	}
	let mut output = PathBuf::new();
	for component in path.components() {
		match component {
			Component::Normal(part) => output.push(part),
			_ => return Err(invalid("OCI layer path is not normalized")),
		}
	}
	if output.as_os_str().is_empty() {
		return Err(invalid("OCI layer path is empty"));
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

fn apply_whiteout(root: &Path, relative: &Path) -> Result<bool, ProtocolError> {
	let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
		return Ok(false);
	};
	let Some(whiteout) = name.strip_prefix(".wh.") else {
		return Ok(false);
	};
	let parent = relative.parent().unwrap_or_else(|| Path::new(""));
	ensure_safe_parents(root, relative)?;
	let directory = root.join(parent);
	if whiteout == ".wh..opq" {
		for entry in fs::read_dir(&directory)
			.map_err(|_| invalid("failed to apply opaque whiteout"))?
		{
			remove_path(
				&entry.map_err(|_| invalid("invalid whiteout target"))?.path(),
			)?;
		}
	} else {
		if whiteout.is_empty() || whiteout.contains('/') {
			return Err(invalid("invalid OCI whiteout"));
		}
		remove_path_if_present(&directory.join(whiteout))?;
	}
	Ok(true)
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
	let mtime = i64::try_from(
		header.mtime().map_err(|_| invalid("invalid layer mtime"))?,
	)
	.map_err(|_| invalid("layer mtime exceeds Linux range"))?;
	let mut xattrs = Vec::new();
	if let Some(extensions) = entry
		.pax_extensions()
		.map_err(|_| invalid("invalid layer PAX metadata"))?
	{
		for extension in extensions {
			let extension =
				extension.map_err(|_| invalid("invalid layer PAX record"))?;
			let Some(name) =
				extension.key_bytes().strip_prefix(b"SCHILY.xattr.")
			else {
				continue;
			};
			validate_xattr(name)?;
			xattrs.push((
				CString::new(name)
					.map_err(|_| invalid("invalid layer xattr name"))?,
				extension.value_bytes().to_vec(),
			));
		}
	}
	Ok(Metadata { path, mode, uid, gid, mtime, xattrs, symlink })
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
	let times = [
		libc::timespec { tv_sec: metadata.mtime, tv_nsec: 0 },
		libc::timespec { tv_sec: metadata.mtime, tv_nsec: 0 },
	];
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
		vec![normalized_container_path(executable)?]
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
	for candidate in candidates {
		let host = resolve_rootfs_path(rootfs, &candidate)?;
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
		let metadata = fs::symlink_metadata(&candidate)
			.map_err(|_| invalid("OCI process path does not exist"))?;
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
	Ok(rootfs.join(resolved))
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

fn parse_passwd(rootfs: &Path) -> Result<Vec<Passwd>, ProtocolError> {
	let text =
		fs::read_to_string(rootfs.join("etc/passwd")).unwrap_or_default();
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
	let text = fs::read_to_string(rootfs.join("etc/group")).unwrap_or_default();
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
