//! Docker program and access-policy types.

use std::{
	ffi::OsString,
	path::{Path, PathBuf},
};

use crate::{ImageRef, RunnerError};

/// Program run inside a Docker container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerProgram {
	/// Use the image entrypoint.
	ImageEntrypoint {
		/// Docker image.
		image: ImageRef,
	},
	/// Run a mounted binary inside a generic image.
	MountedBinary {
		/// Docker image.
		image: ImageRef,
		/// Binary path visible inside the container.
		path: PathBuf,
	},
}

impl DockerProgram {
	fn image(&self) -> &ImageRef {
		match self {
			Self::ImageEntrypoint { image }
			| Self::MountedBinary { image, .. } => image,
		}
	}

	pub(crate) fn append_program_args(&self, args: &mut Vec<OsString>) {
		args.push(self.image().as_str().into());
		if let Self::MountedBinary { path, .. } = self {
			args.push(path.clone().into_os_string());
		}
	}
}

/// Docker bind mount used by runner containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerMount {
	/// Host path.
	pub host_path: PathBuf,
	/// Container path.
	pub container_path: PathBuf,
	/// Whether to mount read-only.
	pub read_only: bool,
}

impl DockerMount {
	pub(crate) fn to_docker_arg(&self) -> OsString {
		let suffix = if self.read_only { ":ro" } else { "" };
		format!(
			"{}:{}{}",
			self.host_path.display(),
			self.container_path.display(),
			suffix
		)
		.into()
	}

	pub(crate) fn translate_path(&self, path: &Path) -> Option<PathBuf> {
		let suffix = path.strip_prefix(&self.host_path).ok()?;
		Some(self.container_path.join(suffix))
	}
}

/// Mount and privilege policy for one class of Docker command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerRunSpec {
	/// Bind mounts passed to the container.
	pub mounts: Vec<DockerMount>,
	/// Whether the container runs with `--privileged`.
	pub privileged: bool,
}

impl DockerRunSpec {
	pub(crate) fn translate_path(&self, path: &Path) -> Option<PathBuf> {
		self.mounts
			.iter()
			.filter_map(|mount| {
				mount.translate_path(path).map(|translated| {
					(mount.host_path.components().count(), translated)
				})
			})
			.max_by_key(|(prefix_components, _)| *prefix_components)
			.map(|(_, translated)| translated)
	}
}

/// Docker volume-backed socket shared by QEMU tool containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerVolumeSocket {
	/// Docker volume name.
	pub volume_name: String,
	/// Absolute socket path inside the QEMU tool containers.
	pub socket_path: PathBuf,
}

impl DockerVolumeSocket {
	pub(crate) fn docker_mount_args(
		&self,
	) -> Result<Vec<OsString>, RunnerError> {
		let target = self.socket_path.parent().ok_or_else(|| {
			RunnerError::InvalidConfig(
				"qemu.qemu_tool_vhost_socket.socket_path must have a parent"
					.to_string(),
			)
		})?;
		Ok(vec![
			"--mount".into(),
			format!(
				"type=volume,src={},dst={}",
				self.volume_name,
				target.display()
			)
			.into(),
		])
	}
}
