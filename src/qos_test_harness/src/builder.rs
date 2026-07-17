//! Typed artifact builders used by the integration harness.

use std::{
	collections::BTreeMap,
	ffi::OsString,
	path::{Path, PathBuf},
	process::{Command, Stdio},
};

use crate::{BinaryArtifact, Eif, ImageRef, Pivot};

/// Generic builder that produces a typed artifact.
#[allow(async_fn_in_trait)]
pub trait Builder<T> {
	/// Build the artifact.
	async fn build(&self) -> Result<T, BuildError>;
}

/// Selects which of two configured artifact pipelines to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
	/// Execute the reproducible or production-equivalent pipeline.
	Slow,
	/// Execute the shorter developer-iteration pipeline.
	Fast,
}

/// Delegates a build to one of two supplied builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSelector<Slow, Fast> {
	/// Pipeline to execute.
	pub mode: BuildMode,
	/// Builder used in [`BuildMode::Slow`] mode.
	pub slow: Slow,
	/// Builder used in [`BuildMode::Fast`] mode.
	pub fast: Fast,
}

impl<T, Slow, Fast> Builder<T> for BuildSelector<Slow, Fast>
where
	Slow: Builder<T>,
	Fast: Builder<T>,
{
	async fn build(&self) -> Result<T, BuildError> {
		match self.mode {
			BuildMode::Slow => self.slow.build().await,
			BuildMode::Fast => self.fast.build().await,
		}
	}
}

/// Cargo build profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoProfile {
	/// Cargo release profile.
	Release,
	/// Named cargo profile.
	Named(String),
}

impl CargoProfile {
	fn build_args(&self) -> Vec<OsString> {
		match self {
			Self::Release => vec!["--release".into()],
			Self::Named(profile) => vec!["--profile".into(), profile.into()],
		}
	}

	fn output_dir(&self) -> &str {
		match self {
			Self::Release => "release",
			Self::Named(profile) => profile,
		}
	}
}

/// Errors produced by builders.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
	/// Manifest template could not be constructed from test fixtures.
	#[error("manifest template error: {0}")]
	Manifest(String),
	/// Image references may not be empty.
	#[error("image reference may not be empty")]
	EmptyImageRef,
	/// Builder input path was invalid.
	#[error("{name} path may not be empty")]
	EmptyPath {
		/// Input name.
		name: &'static str,
	},
	/// Docker command failed.
	#[error(
		"docker command failed: {command}; status: {status}; stderr: {stderr}"
	)]
	Docker {
		/// Command line.
		command: String,
		/// Process status.
		status: String,
		/// Captured stderr.
		stderr: String,
	},
	/// Local command failed.
	#[error("command failed: {command}; status: {status}; stderr: {stderr}")]
	Command {
		/// Command line.
		command: String,
		/// Process status.
		status: String,
		/// Captured stderr.
		stderr: String,
	},
	/// IO error.
	#[error(transparent)]
	Io(#[from] std::io::Error),
}

/// Builds a local cargo binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoBinaryBuilder {
	/// Workspace root.
	pub root: PathBuf,
	/// Cargo package.
	pub package: String,
	/// Optional manifest path for packages outside the workspace.
	pub manifest_path: Option<PathBuf>,
	/// Optional binary name.
	pub bin: Option<String>,
	/// Rust target triple.
	pub target: String,
	/// Cargo profile.
	pub profile: CargoProfile,
	/// Optional target directory.
	pub target_dir: Option<PathBuf>,
	/// Cargo features.
	pub features: Vec<String>,
	/// Whether to pass `--no-default-features`.
	pub no_default_features: bool,
	/// Environment variables for cargo.
	pub env: BTreeMap<String, String>,
}

impl CargoBinaryBuilder {
	/// Create a cargo binary builder.
	pub fn new(
		root: impl Into<PathBuf>,
		package: impl Into<String>,
		target: impl Into<String>,
		profile: CargoProfile,
	) -> Result<Self, BuildError> {
		let root = root.into();
		ensure_non_empty_path("root", &root)?;
		Ok(Self {
			root,
			package: package.into(),
			manifest_path: None,
			bin: None,
			target: target.into(),
			profile,
			target_dir: None,
			features: Vec::new(),
			no_default_features: false,
			env: BTreeMap::new(),
		})
	}

	/// Set a manifest path instead of selecting a workspace package.
	#[must_use]
	pub fn with_manifest_path(mut self, path: impl Into<PathBuf>) -> Self {
		self.manifest_path = Some(path.into());
		self
	}

	/// Set the binary name.
	#[must_use]
	pub fn with_bin(mut self, bin: impl Into<String>) -> Self {
		self.bin = Some(bin.into());
		self
	}

	/// Set `CARGO_TARGET_DIR` and use it for the expected output path.
	#[must_use]
	pub fn with_target_dir(mut self, path: impl Into<PathBuf>) -> Self {
		self.target_dir = Some(path.into());
		self
	}

	/// Set cargo features.
	#[must_use]
	pub fn with_features<I, S>(mut self, features: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		self.features = features.into_iter().map(Into::into).collect();
		self
	}

	/// Pass `--no-default-features`.
	#[must_use]
	pub fn with_no_default_features(mut self) -> Self {
		self.no_default_features = true;
		self
	}

	/// Add an environment variable.
	#[must_use]
	pub fn with_env(
		mut self,
		key: impl Into<String>,
		value: impl Into<String>,
	) -> Self {
		self.env.insert(key.into(), value.into());
		self
	}

	/// Cargo args for this build.
	#[must_use]
	pub fn cargo_args(&self) -> Vec<OsString> {
		let mut args = vec!["build".into()];
		if let Some(manifest_path) = &self.manifest_path {
			args.extend([
				"--manifest-path".into(),
				manifest_path.clone().into_os_string(),
			]);
		} else {
			args.extend(["-p".into(), self.package.clone().into()]);
		}
		if let Some(bin) = &self.bin {
			args.extend(["--bin".into(), bin.clone().into()]);
		}
		if !self.features.is_empty() {
			args.extend(["--features".into(), self.features.join(",").into()]);
		}
		if self.no_default_features {
			args.push("--no-default-features".into());
		}
		args.push("--locked".into());
		args.extend(["--target".into(), self.target.clone().into()]);
		args.extend(self.profile.build_args());
		args
	}

	/// Expected output binary path.
	#[must_use]
	pub fn output_path(&self) -> PathBuf {
		self.target_dir
			.clone()
			.unwrap_or_else(|| self.root.join("target"))
			.join(&self.target)
			.join(self.profile.output_dir())
			.join(self.bin.as_deref().unwrap_or(&self.package))
	}
}

impl Builder<BinaryArtifact> for CargoBinaryBuilder {
	async fn build(&self) -> Result<BinaryArtifact, BuildError> {
		let mut command = Command::new("cargo");
		command.current_dir(&self.root).args(self.cargo_args());
		if let Some(target_dir) = &self.target_dir {
			command.env("CARGO_TARGET_DIR", target_dir);
		}
		for (key, value) in &self.env {
			command.env(key, value);
		}
		run_local_command(&mut command)?;
		Ok(BinaryArtifact { path: self.output_path() })
	}
}

/// Builds one or more repository artifacts through Make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeTargetBuilder {
	/// Repository root containing the Makefile.
	pub root: PathBuf,
	/// Make targets to build.
	pub targets: Vec<String>,
	/// Make executable.
	pub make_bin: PathBuf,
}

impl MakeTargetBuilder {
	/// Create a builder for `targets` in `root`.
	pub fn new<I, S>(
		root: impl Into<PathBuf>,
		targets: I,
	) -> Result<Self, BuildError>
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		let root = root.into();
		ensure_non_empty_path("root", &root)?;
		Ok(Self {
			root,
			targets: targets.into_iter().map(Into::into).collect(),
			make_bin: PathBuf::from("make"),
		})
	}

	/// Override the Make executable.
	#[must_use]
	pub fn with_make_bin(mut self, make_bin: impl Into<PathBuf>) -> Self {
		self.make_bin = make_bin.into();
		self
	}
}

impl Builder<()> for MakeTargetBuilder {
	async fn build(&self) -> Result<(), BuildError> {
		run_local_command(
			Command::new(&self.make_bin)
				.current_dir(&self.root)
				.args(&self.targets),
		)
	}
}

/// Loads an OCI image layout into Docker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayoutLoadBuilder {
	layout_dir: PathBuf,
	docker_bin: PathBuf,
}

impl OciLayoutLoadBuilder {
	/// Create a builder for the OCI layout in `layout_dir`.
	pub fn new(layout_dir: impl Into<PathBuf>) -> Result<Self, BuildError> {
		let layout_dir = layout_dir.into();
		ensure_non_empty_path("layout_dir", &layout_dir)?;
		Ok(Self { layout_dir, docker_bin: PathBuf::from("docker") })
	}

	/// Override the Docker executable.
	#[must_use]
	pub fn with_docker_bin(mut self, docker_bin: impl Into<PathBuf>) -> Self {
		self.docker_bin = docker_bin.into();
		self
	}
}

impl Builder<()> for OciLayoutLoadBuilder {
	async fn build(&self) -> Result<(), BuildError> {
		let mut tar = Command::new("tar")
			.current_dir(&self.layout_dir)
			.args(["-cf", "-", "."])
			.stdout(Stdio::piped())
			.spawn()?;
		let tar_stdout = tar.stdout.take().expect("tar stdout is piped");
		let mut docker = Command::new(&self.docker_bin)
			.arg("load")
			.stdin(Stdio::from(tar_stdout))
			.spawn()?;
		let docker_status = docker.wait()?;
		let tar_status = tar.wait()?;
		if tar_status.success() && docker_status.success() {
			return Ok(());
		}
		Err(BuildError::Docker {
			command: format!(
				"tar -cf - . | {} load",
				self.docker_bin.display()
			),
			status: format!("tar: {tar_status}; docker: {docker_status}"),
			stderr: String::new(),
		})
	}
}

/// Pulls a configured OCI image with Docker.
#[derive(Debug, Clone)]
pub struct ImagePullBuilder {
	image: ImageRef,
	docker_bin: PathBuf,
}

impl ImagePullBuilder {
	/// Create a builder for `image`.
	#[must_use]
	pub fn new(image: ImageRef) -> Self {
		Self { image, docker_bin: PathBuf::from("docker") }
	}

	/// Override the Docker binary.
	#[must_use]
	pub fn with_docker_bin(mut self, docker_bin: impl Into<PathBuf>) -> Self {
		self.docker_bin = docker_bin.into();
		self
	}
}

impl Builder<ImageRef> for ImagePullBuilder {
	async fn build(&self) -> Result<ImageRef, BuildError> {
		run_command(
			Command::new(&self.docker_bin).arg("pull").arg(self.image.as_str()),
		)?;
		Ok(self.image.clone())
	}
}

/// Extracts a single file from an OCI image.
#[derive(Debug, Clone)]
pub struct ImageFileExtractBuilder {
	image: ImageRef,
	image_path: PathBuf,
	output_path: PathBuf,
	docker_bin: PathBuf,
	container_name: String,
}

impl ImageFileExtractBuilder {
	/// Create an image-file extractor.
	pub fn new(
		image: ImageRef,
		image_path: impl Into<PathBuf>,
		output_path: impl Into<PathBuf>,
	) -> Result<Self, BuildError> {
		let image_path = image_path.into();
		let output_path = output_path.into();
		ensure_non_empty_path("image_path", &image_path)?;
		ensure_non_empty_path("output_path", &output_path)?;
		let container_name =
			format!("qos-test-harness-extract-{}", std::process::id());
		Ok(Self {
			image,
			image_path,
			output_path,
			docker_bin: PathBuf::from("docker"),
			container_name,
		})
	}

	/// Override the Docker binary.
	#[must_use]
	pub fn with_docker_bin(mut self, docker_bin: impl Into<PathBuf>) -> Self {
		self.docker_bin = docker_bin.into();
		self
	}
}

impl Builder<Pivot> for ImageFileExtractBuilder {
	async fn build(&self) -> Result<Pivot, BuildError> {
		let cleanup = DockerContainerCleanup {
			docker_bin: self.docker_bin.clone(),
			name: self.container_name.clone(),
		};
		cleanup.remove();
		run_command(
			Command::new(&self.docker_bin)
				.arg("create")
				.arg("--name")
				.arg(&self.container_name)
				.arg(self.image.as_str()),
		)?;

		let source =
			format!("{}:{}", self.container_name, self.image_path.display());
		run_command(
			Command::new(&self.docker_bin)
				.arg("cp")
				.arg(source)
				.arg(&self.output_path),
		)?;
		Ok(Pivot { path: self.output_path.clone() })
	}
}

struct DockerContainerCleanup {
	docker_bin: PathBuf,
	name: String,
}

impl DockerContainerCleanup {
	fn remove(&self) {
		drop(
			Command::new(&self.docker_bin)
				.arg("rm")
				.arg("-f")
				.arg(&self.name)
				.output(),
		);
	}
}

impl Drop for DockerContainerCleanup {
	fn drop(&mut self) {
		self.remove();
	}
}

/// Base images used to assemble a QEMU EIF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuEifBaseImages {
	/// Image used as the shell-bearing EIF assembly stage.
	pub build: ImageRef,
	/// Image containing `eif_build`.
	pub eif_build: ImageRef,
	/// Image containing `gen_init_cpio`.
	pub gen_initramfs: ImageRef,
	/// Image containing Nitro-compatible kernel artifacts.
	pub linux_nitro: ImageRef,
	/// Image containing libunwind runtime files.
	pub libunwind: ImageRef,
	/// Image containing `ip`.
	pub iproute2: ImageRef,
	/// Image containing the musl loader/runtime.
	pub musl: ImageRef,
}

/// Builds a QEMU EIF from prebuilt local binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrebuiltQemuEifBuilder {
	/// Work directory used for the Docker build context.
	pub work_dir: PathBuf,
	/// Output EIF path.
	pub output_path: PathBuf,
	/// Optional PCR output path.
	pub pcrs_path: Option<PathBuf>,
	/// Prebuilt `init` binary.
	pub init: BinaryArtifact,
	/// Prebuilt `egress` binary.
	pub egress: BinaryArtifact,
	/// Base images used by the EIF assembly Containerfile.
	pub base_images: QemuEifBaseImages,
}

impl PrebuiltQemuEifBuilder {
	/// Create a prebuilt-binary QEMU EIF builder.
	pub fn new(
		work_dir: impl Into<PathBuf>,
		output_path: impl Into<PathBuf>,
		init: BinaryArtifact,
		egress: BinaryArtifact,
		base_images: QemuEifBaseImages,
	) -> Result<Self, BuildError> {
		let work_dir = work_dir.into();
		let output_path = output_path.into();
		ensure_non_empty_path("work_dir", &work_dir)?;
		ensure_non_empty_path("output_path", &output_path)?;
		ensure_non_empty_path("init.path", &init.path)?;
		ensure_non_empty_path("egress.path", &egress.path)?;
		Ok(Self {
			work_dir,
			output_path,
			pcrs_path: None,
			init,
			egress,
			base_images,
		})
	}

	/// Set the optional PCR output path.
	#[must_use]
	pub fn with_pcrs_path(mut self, path: impl Into<PathBuf>) -> Self {
		self.pcrs_path = Some(path.into());
		self
	}

	fn context_dir(&self) -> PathBuf {
		self.work_dir.join("prebuilt-qemu-eif-context")
	}

	fn containerfile() -> PathBuf {
		PathBuf::from(env!("CARGO_MANIFEST_DIR"))
			.join("docker/qemu_eif_prebuilt.Containerfile")
	}

	fn tag(&self) -> String {
		format!("qos-test-harness-prebuilt-eif:{}", std::process::id())
	}

	fn container_name(&self) -> String {
		format!("qos-test-harness-prebuilt-eif-{}", std::process::id())
	}

	fn stage_context(&self) -> Result<PathBuf, BuildError> {
		let context_dir = self.context_dir();
		drop(std::fs::remove_dir_all(&context_dir));
		std::fs::create_dir_all(&context_dir)?;
		std::fs::copy(&self.init.path, context_dir.join("init"))?;
		std::fs::copy(&self.egress.path, context_dir.join("egress"))?;
		std::fs::write(
			context_dir.join("resolv.conf"),
			b"nameserver 1.1.1.1\n",
		)?;
		Ok(context_dir)
	}

	fn add_base_image_args(&self, command: &mut Command) {
		for (key, image) in [
			("BUILD_IMAGE", &self.base_images.build),
			("EIF_BUILD_IMAGE", &self.base_images.eif_build),
			("GEN_INITRAMFS_IMAGE", &self.base_images.gen_initramfs),
			("LINUX_NITRO_IMAGE", &self.base_images.linux_nitro),
			("LIBUNWIND_IMAGE", &self.base_images.libunwind),
			("IPROUTE2_IMAGE", &self.base_images.iproute2),
			("MUSL_IMAGE", &self.base_images.musl),
		] {
			command.arg("--build-arg").arg(format!("{key}={image}"));
		}
	}
}

impl Builder<Eif> for PrebuiltQemuEifBuilder {
	async fn build(&self) -> Result<Eif, BuildError> {
		let context_dir = self.stage_context()?;
		let tag = self.tag();
		let container_name = self.container_name();

		let mut build = Command::new("docker");
		build
			.env("DOCKER_BUILDKIT", "1")
			.arg("build")
			.arg("--platform")
			.arg("linux/amd64")
			.arg("--file")
			.arg(Self::containerfile())
			.arg("--tag")
			.arg(&tag);
		self.add_base_image_args(&mut build);
		build.arg(&context_dir);
		run_command(&mut build)?;

		if let Some(parent) = self.output_path.parent() {
			std::fs::create_dir_all(parent)?;
		}
		if let Some(pcrs_path) = &self.pcrs_path
			&& let Some(parent) = pcrs_path.parent()
		{
			std::fs::create_dir_all(parent)?;
		}

		let _cleanup = DockerContainerCleanup {
			docker_bin: PathBuf::from("docker"),
			name: container_name.clone(),
		};
		run_command(
			Command::new("docker")
				.arg("create")
				.arg("--name")
				.arg(&container_name)
				.arg(&tag)
				.arg("true"),
		)?;
		run_command(
			Command::new("docker")
				.arg("cp")
				.arg(format!("{container_name}:/nitro.eif"))
				.arg(&self.output_path),
		)?;
		if let Some(pcrs_path) = &self.pcrs_path {
			run_command(
				Command::new("docker")
					.arg("cp")
					.arg(format!("{container_name}:/nitro.pcrs"))
					.arg(pcrs_path),
			)?;
		}

		Ok(Eif {
			path: self.output_path.clone(),
			pcrs_path: self.pcrs_path.clone(),
		})
	}
}

fn ensure_non_empty_path(
	name: &'static str,
	path: &Path,
) -> Result<(), BuildError> {
	if path.as_os_str().is_empty() {
		return Err(BuildError::EmptyPath { name });
	}
	Ok(())
}

fn run_command(command: &mut Command) -> Result<(), BuildError> {
	let debug = format!("{command:?}");
	let output = command.output()?;
	if output.status.success() {
		return Ok(());
	}
	Err(BuildError::Docker {
		command: debug,
		status: output.status.to_string(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
	})
}

fn run_local_command(command: &mut Command) -> Result<(), BuildError> {
	let debug = format!("{command:?}");
	let output = command.output()?;
	if output.status.success() {
		return Ok(());
	}
	Err(BuildError::Command {
		command: debug,
		status: output.status.to_string(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
	})
}
