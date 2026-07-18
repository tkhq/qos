//! OCI runtime lifecycle backed by `libcontainer`.

use std::path::Path;

#[cfg(target_os = "linux")]
use std::{fs, fs::File};

#[cfg(target_os = "linux")]
use libcontainer::{
	container::{Container, builder::ContainerBuilder},
	syscall::syscall::SyscallType,
};
#[cfg(target_os = "linux")]
use nix::{
	sys::wait::{WaitStatus, waitpid},
	unistd::Pid,
};

/// Create, start, wait for, and tear down one OCI container.
#[cfg(target_os = "linux")]
pub(crate) fn run(
	bundle: &Path,
	state_root: &Path,
	container_id: &str,
	debug: bool,
) -> Result<i32, String> {
	fs::create_dir_all(state_root).map_err(|error| {
		format!("failed to create container state: {error}")
	})?;
	cleanup_stale_container(state_root, container_id)?;

	let mut builder =
		ContainerBuilder::new(container_id.to_string(), SyscallType::Linux)
			.validate_id()
			.map_err(|error| format!("invalid container id: {error}"))?
			.with_root_path(state_root)
			.map_err(|error| {
				format!("invalid container state path: {error}")
			})?;
	if !debug {
		builder = builder
			.with_stdin(open_null()?)
			.with_stdout(open_null()?)
			.with_stderr(open_null()?);
	}

	let mut container = builder
		.as_init(bundle)
		.with_systemd(false)
		.with_detach(true)
		.build()
		.map_err(|error| format!("failed to create container: {error}"))?;
	if let Err(error) = container.start() {
		let _ = container.delete(true);
		return Err(format!("failed to start container: {error}"));
	}
	let pid = container
		.pid()
		.ok_or_else(|| "libcontainer did not report an init pid".to_string())?;
	let pid = Pid::from_raw(pid.as_raw());
	let exit_code = match wait_for_init(pid) {
		Ok(code) => code,
		Err(error) => {
			let _ = container.delete(true);
			return Err(error);
		}
	};
	container
		.delete(true)
		.map_err(|error| format!("failed to delete container: {error}"))?;
	Ok(exit_code)
}

#[cfg(target_os = "linux")]
fn cleanup_stale_container(
	state_root: &Path,
	container_id: &str,
) -> Result<(), String> {
	let container_root = state_root.join(container_id);
	if !container_root.exists() {
		return Ok(());
	}
	if let Ok(mut container) = Container::load(container_root.clone()) {
		container.delete(true).map_err(|error| {
			format!("failed to clean up stale container: {error}")
		})?;
	} else {
		fs::remove_dir_all(&container_root).map_err(|error| {
			format!("failed to remove stale container state: {error}")
		})?;
	}
	Ok(())
}

#[cfg(target_os = "linux")]
fn open_null() -> Result<File, String> {
	File::options()
		.read(true)
		.write(true)
		.open("/dev/null")
		.map_err(|error| format!("failed to open /dev/null: {error}"))
}

#[cfg(target_os = "linux")]
fn wait_for_init(pid: Pid) -> Result<i32, String> {
	match waitpid(pid, None)
		.map_err(|error| format!("failed to wait for container: {error}"))?
	{
		WaitStatus::Exited(_, code) => Ok(code),
		WaitStatus::Signaled(_, signal, _) => Ok(128 + signal as i32),
		status => Err(format!("unexpected container wait status: {status:?}")),
	}
}

/// Container execution is only available in the Linux enclave.
#[cfg(not(target_os = "linux"))]
pub(crate) fn run(
	_bundle: &Path,
	_state_root: &Path,
	_container_id: &str,
	_debug: bool,
) -> Result<i32, String> {
	Err("libcontainer execution requires Linux".to_string())
}
