//! Repo-local Docker/QEMU artifact preparation.

use std::{
	fs::{File, OpenOptions},
	net::TcpListener,
	path::{Path, PathBuf},
	process::Command,
};

use qos_test_harness::{
	BinaryArtifact, BuildError, BuildMode, BuildSelector, Builder,
	CargoBinaryBuilder, CargoProfile, DockerHostQemuNitroRunner,
	ImageFileExtractBuilder, ImageRef, MakeTargetBuilder, ManifestBuilder,
	OciLayoutLoadBuilder, Pivot, PrebuiltQemuEifBuilder, RunnerError,
};

use super::repo_defaults;

const FAST_TARGET: &str = "x86_64-unknown-linux-musl";

/// Inputs for preparing one Docker/QEMU test runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerHostQemuNitroPreparation {
	/// Repository root.
	pub(crate) root: PathBuf,
	/// Docker binary.
	pub(crate) docker_bin: PathBuf,
	/// Artifact build mode.
	pub(crate) build_mode: BuildMode,
	/// Images supplied by CI instead of built from the repository checkout.
	pub(crate) ci_images: Option<QemuCiImages>,
}

/// PR-built images consumed by the `qemu-ci` test mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuCiImages {
	pub(crate) enclave: ImageRef,
	pub(crate) host: ImageRef,
	pub(crate) bridge: ImageRef,
	pub(crate) client: ImageRef,
	pub(crate) pivot: ImageRef,
}

impl QemuCiImages {
	pub(crate) fn from_env() -> Result<Self, PreparationError> {
		Ok(Self {
			enclave: required_image_env("QOS_TEST_QEMU_ENCLAVE_IMAGE")?,
			host: required_image_env("QOS_TEST_QEMU_HOST_IMAGE")?,
			bridge: required_image_env("QOS_TEST_QEMU_BRIDGE_IMAGE")?,
			client: required_image_env("QOS_TEST_QEMU_CLIENT_IMAGE")?,
			pivot: required_image_env("QOS_TEST_QEMU_PIVOT_IMAGE")?,
		})
	}
}

/// Prepared Docker/QEMU runtime with an exclusive harness session.
#[derive(Debug)]
pub(crate) struct PreparedDockerHostQemuNitro {
	/// Ready-to-start runner.
	pub(crate) runner: DockerHostQemuNitroRunner,
	/// Signed-echo pivot produced by the selected artifact pipeline.
	pub(crate) pivot: Pivot,
	root: PathBuf,
	/// Holds the exclusive Docker/QEMU harness lock for this prepared test.
	_session: DockerHostQemuNitroSession,
}

impl PreparedDockerHostQemuNitro {
	/// Create the fixture-backed manifest template for `pivot`.
	pub(crate) fn manifest_template(
		&self,
		pivot: &Pivot,
	) -> Result<ManifestBuilder, BuildError> {
		repo_defaults::test_manifest_template(&self.root, pivot)
	}
}

#[derive(Debug)]
struct DockerHostQemuNitroSession {
	work_dir: PathBuf,
	_lock: File,
}

impl DockerHostQemuNitroSession {
	fn acquire(root: &Path) -> Result<Self, std::io::Error> {
		let work_dir =
			root.join("target/qos-test-harness/docker-host-qemu-nitro");
		std::fs::create_dir_all(&work_dir)?;
		let lock = OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.open(work_dir.join(".lock"))?;
		lock.lock()?;
		Ok(Self { work_dir, _lock: lock })
	}
}

/// Failure while preparing repo-local Docker/QEMU artifacts.
#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
	/// Artifact builder failure.
	#[error(transparent)]
	Build(#[from] BuildError),
	/// Runner configuration failure.
	#[error(transparent)]
	Runner(#[from] RunnerError),
	/// Local command IO failure.
	#[error(transparent)]
	Io(#[from] std::io::Error),
	/// Local command returned a failure status.
	#[error("{0}")]
	Command(String),
}

impl DockerHostQemuNitroPreparation {
	/// Prepare shared Docker/QEMU infrastructure and acquire its session lock.
	pub(crate) async fn prepare(
		self,
	) -> Result<PreparedDockerHostQemuNitro, PreparationError> {
		let session = DockerHostQemuNitroSession::acquire(&self.root)?;
		let (host_port, ingress_port) = unused_local_port_pair()?;
		build_qemu_tool_image(&self)?;
		build_egress_tools_image(&self)?;

		let defaults = repo_defaults::DockerHostQemuNitroDefaults {
			root: self.root.clone(),
			work_dir: session.work_dir.clone(),
			docker_bin: self.docker_bin.clone(),
			host_port,
			ingress_port,
		};

		let (pivot, runner_spec) = if let Some(images) = &self.ci_images {
			let pivot = prepare_ci_artifacts(
				&self,
				&session.work_dir,
				&images.enclave,
				&images.pivot,
			)
			.await?;
			let runner_spec = repo_defaults::docker_host_qemu_nitro_spec(
				defaults,
				repo_defaults::DockerHostQemuNitroImages {
					host: images.host.clone(),
					bridge: images.bridge.clone(),
					client: images.client.clone(),
				},
			)?;
			(pivot, runner_spec)
		} else {
			let selector = BuildSelector {
				mode: self.build_mode,
				slow: RepositoryArtifactsBuilder {
					preparation: &self,
					work_dir: &session.work_dir,
				},
				fast: FastCargoArtifactsBuilder {
					preparation: &self,
					work_dir: &session.work_dir,
				},
			};
			let pivot = selector.build().await?;
			let runner_spec = match self.build_mode {
				BuildMode::Slow => repo_defaults::docker_host_qemu_nitro_spec(
					defaults,
					repo_defaults::local_qemu_images()?,
				)?,
				BuildMode::Fast => {
					repo_defaults::docker_host_qemu_nitro_fast_spec(defaults)?
				}
			};
			(pivot, runner_spec)
		};

		Ok(PreparedDockerHostQemuNitro {
			runner: DockerHostQemuNitroRunner::new(runner_spec),
			pivot,
			root: self.root,
			_session: session,
		})
	}
}

struct RepositoryArtifactsBuilder<'a> {
	preparation: &'a DockerHostQemuNitroPreparation,
	work_dir: &'a Path,
}

impl Builder<Pivot> for RepositoryArtifactsBuilder<'_> {
	async fn build(&self) -> Result<Pivot, BuildError> {
		prepare_repository_artifacts(self.preparation, self.work_dir)
			.await
			.map_err(preparation_error_to_build_error)
	}
}

struct FastCargoArtifactsBuilder<'a> {
	preparation: &'a DockerHostQemuNitroPreparation,
	work_dir: &'a Path,
}

impl Builder<Pivot> for FastCargoArtifactsBuilder<'_> {
	async fn build(&self) -> Result<Pivot, BuildError> {
		prepare_fast_artifacts(self.preparation, self.work_dir)
			.await
			.map_err(preparation_error_to_build_error)
	}
}

fn preparation_error_to_build_error(error: PreparationError) -> BuildError {
	match error {
		PreparationError::Build(error) => error,
		PreparationError::Io(error) => BuildError::Io(error),
		PreparationError::Runner(error) => BuildError::Command {
			command: "construct QOS Docker/QEMU runner specification"
				.to_string(),
			status: "invalid configuration".to_string(),
			stderr: error.to_string(),
		},
		PreparationError::Command(error) => BuildError::Command {
			command: "prepare QOS Docker/QEMU artifacts".to_string(),
			status: "failed".to_string(),
			stderr: error,
		},
	}
}

fn build_qemu_tool_image(
	preparation: &DockerHostQemuNitroPreparation,
) -> Result<(), PreparationError> {
	let image = repo_defaults::local_image("qos_test_harness_nitro_tools")?;
	run_checked(
		Command::new(&preparation.docker_bin)
			.current_dir(&preparation.root)
			.env("DOCKER_BUILDKIT", "1")
			.args([
				"build",
				"--platform",
				"linux/amd64",
				"--file",
				"src/qos_test_harness/docker/nitro_tools.Containerfile",
				"--tag",
				image.as_str(),
				"src/qos_test_harness/docker",
			]),
		"build QEMU tool image",
	)
}

fn build_egress_tools_image(
	preparation: &DockerHostQemuNitroPreparation,
) -> Result<(), PreparationError> {
	let platform = match std::env::consts::ARCH {
		"aarch64" => "linux/arm64",
		"x86_64" => "linux/amd64",
		arch => {
			return Err(PreparationError::Command(format!(
				"unsupported egress tools host architecture: {arch}"
			)));
		}
	};
	let image = repo_defaults::local_image("qos_test_harness_egress_tools")?;
	run_checked(
		Command::new(&preparation.docker_bin)
			.current_dir(&preparation.root)
			.env("DOCKER_BUILDKIT", "1")
			.args([
				"build",
				"--platform",
				platform,
				"--file",
				"src/qos_test_harness/docker/egress_tools.Containerfile",
				"--tag",
				image.as_str(),
				"src/qos_test_harness/docker",
			]),
		"build egress tools image",
	)
}

async fn prepare_repository_artifacts(
	preparation: &DockerHostQemuNitroPreparation,
	work_dir: &Path,
) -> Result<Pivot, PreparationError> {
	MakeTargetBuilder::new(
		&preparation.root,
		[
			"out/qos_enclave_egress/index.json",
			"out/qos_host_qemu/index.json",
			"out/qos_bridge_qemu/index.json",
			"out/qos_client/index.json",
			"out/signed_echo/index.json",
		],
	)?
	.build()
	.await?;

	for name in [
		"qos_enclave_egress",
		"qos_host_qemu",
		"qos_bridge_qemu",
		"qos_client",
		"signed_echo",
	] {
		OciLayoutLoadBuilder::new(preparation.root.join("out").join(name))?
			.with_docker_bin(&preparation.docker_bin)
			.build()
			.await?;
	}
	extract_eif(
		preparation,
		&repo_defaults::local_image("qos_enclave_egress")?,
	)
	.await?;
	extract_pivot(
		preparation,
		work_dir,
		&repo_defaults::local_image("signed_echo")?,
	)
	.await
}

async fn prepare_ci_artifacts(
	preparation: &DockerHostQemuNitroPreparation,
	work_dir: &Path,
	enclave_image: &ImageRef,
	pivot_image: &ImageRef,
) -> Result<Pivot, PreparationError> {
	extract_eif(preparation, enclave_image).await?;
	extract_pivot(preparation, work_dir, pivot_image).await
}

async fn extract_eif(
	preparation: &DockerHostQemuNitroPreparation,
	image: &ImageRef,
) -> Result<(), PreparationError> {
	std::fs::create_dir_all(preparation.root.join("out"))?;
	ImageFileExtractBuilder::new(
		image.clone(),
		"/nitro.eif",
		preparation.root.join("out/nitro.eif"),
	)?
	.with_docker_bin(&preparation.docker_bin)
	.build()
	.await?;
	Ok(())
}

async fn extract_pivot(
	preparation: &DockerHostQemuNitroPreparation,
	work_dir: &Path,
	image: &ImageRef,
) -> Result<Pivot, PreparationError> {
	let artifacts_dir = work_dir.join("artifacts");
	std::fs::create_dir_all(&artifacts_dir)?;
	let path = ImageFileExtractBuilder::new(
		image.clone(),
		"/tvc_app",
		artifacts_dir.join("signed_echo"),
	)?
	.with_docker_bin(&preparation.docker_bin)
	.build()
	.await
	.map_err(PreparationError::from)?;
	Ok(Pivot { path })
}

async fn prepare_fast_artifacts(
	preparation: &DockerHostQemuNitroPreparation,
	work_dir: &Path,
) -> Result<Pivot, PreparationError> {
	let root = &preparation.root;
	let init = fast_builder(CargoBinaryBuilder::new(
		root,
		"init",
		FAST_TARGET,
		CargoProfile::Release,
	)?)
	.with_manifest_path(root.join("src/init/Cargo.toml"))
	.with_target_dir(root.join("target"))
	.with_features(["egress"])
	.build()
	.await?;
	let egress = fast_builder(CargoBinaryBuilder::new(
		root,
		"qos_bridge",
		FAST_TARGET,
		CargoProfile::Named("release-panic-abort".to_string()),
	)?)
	.with_bin("egress")
	.with_features(["egress"])
	.with_no_default_features()
	.build()
	.await?;

	for builder in [
		fast_builder(CargoBinaryBuilder::new(
			root,
			"qos_host",
			FAST_TARGET,
			CargoProfile::Release,
		)?)
		.with_features(["qemu"]),
		fast_builder(CargoBinaryBuilder::new(
			root,
			"qos_bridge",
			FAST_TARGET,
			CargoProfile::Release,
		)?)
		.with_bin("ingress")
		.with_features(["egress", "qemu"]),
		fast_builder(CargoBinaryBuilder::new(
			root,
			"qos_client",
			FAST_TARGET,
			CargoProfile::Release,
		)?)
		.with_no_default_features(),
	] {
		let _: BinaryArtifact = builder.build().await?;
	}
	let pivot = fast_builder(CargoBinaryBuilder::new(
		root,
		"signed_echo",
		FAST_TARGET,
		CargoProfile::Release,
	)?)
	.build()
	.await?;

	PrebuiltQemuEifBuilder::new(
		work_dir,
		work_dir.join("nitro.eif"),
		init,
		egress,
		repo_defaults::qemu_eif_base_images()?,
	)?
	.with_pcrs_path(work_dir.join("nitro.pcrs"))
	.build()
	.await?;
	Ok(Pivot { path: pivot.path })
}

fn unused_local_port_pair() -> Result<(u16, u16), std::io::Error> {
	let host = TcpListener::bind(("127.0.0.1", 0))?;
	let ingress = TcpListener::bind(("127.0.0.1", 0))?;
	Ok((host.local_addr()?.port(), ingress.local_addr()?.port()))
}

fn fast_builder(builder: CargoBinaryBuilder) -> CargoBinaryBuilder {
	builder
		.with_env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", "rust-lld")
}

fn required_image_env(
	name: &'static str,
) -> Result<ImageRef, PreparationError> {
	let value = std::env::var(name).map_err(|_| {
		PreparationError::Command(format!(
			"{name} must be set when the qemu-ci feature is enabled"
		))
	})?;
	ImageRef::new(value).map_err(PreparationError::from)
}

fn run_checked(
	command: &mut Command,
	label: &str,
) -> Result<(), PreparationError> {
	let status = command.status()?;
	if status.success() {
		Ok(())
	} else {
		Err(PreparationError::Command(format!("{label} failed with {status}")))
	}
}
