use std::{
	collections::BTreeMap,
	fs::{self, File},
	io::Write,
	os::unix::fs::PermissionsExt,
	path::{Path, PathBuf},
	process::{Child, Command, Stdio},
	thread,
	time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
	AppArtifact, AppEndpoint, ArtifactBuildPlan, ArtifactBuildRequest,
	ArtifactBuilder, ArtifactRequest, BuildArtifact, BuildError, BuildKey,
	BuildOutput, BuildProfile, BuildRecord, BuilderKind, HostBinary,
	HostRunnerKind, HttpResponse, RunnerError, RunnerKind, RunningApp,
	StartAppSpec, TestOutcome, TestRunner, http_get, http_post,
	read_build_record, run_command, sha256_file_hex, sha256_hex,
	workspace_state, write_build_record,
};

const SIGNED_ECHO_BIN: &str = "signed_echo";
const NESTED_PARENT_INIT_BIN: &str = "nested_parent_init";
const QOS_HOST_BIN: &str = "qos_host";
const QOS_CLIENT_BIN: &str = "qos_client";
const QOS_BRIDGE_BIN: &str = "qos_bridge";
const X86_64_LINUX_MUSL_TARGET: &str = "x86_64-unknown-linux-musl";
const DEFAULT_PARENT_CONTROL_PORT: u16 = 3001;
const DEFAULT_PARENT_APP_PORT: u16 = 3000;
const DEFAULT_NESTED_GUEST_CID: u32 = 4;
const DEFAULT_NESTED_FORWARD_CID: u32 = 1;
const DEFAULT_NESTED_CORE_PORT: u32 = 3;
const DEFAULT_OUTER_KERNEL_CMDLINE: &str =
	"console=ttyS0 panic=1 reboot=k root=/dev/vda rw init=/init";
const DEFAULT_OUTER_NET_DEVICE: &str = "virtio-net-pci,netdev=parentnet";
const DEFAULT_PARENT_QEMU_PATH: &str = "/tools/qemu-system-x86_64";
const DEFAULT_PARENT_VHOST_VSOCK_PATH: &str = "/tools/vhost-device-vsock";
const DEFAULT_VHOST_SOCKET_PATH: &str = "/tmp/qos-nitro-vhost.socket";
const DEFAULT_INNER_QEMU_ID: &str = "qos-test-harness";
const NESTED_NITRO_CONTAINERFILE: &str = "Containerfile.qemu";
const PARENT_WORK_DIR_METADATA: &str = "parent_work_dir";
const PARENT_ROOT_IMAGE_PATH_METADATA: &str = "parent_root_image_path";
const PARENT_ROOT_IMAGE_SHA256_METADATA: &str = "parent_root_image_sha256";
const OUTER_KERNEL_PATH_METADATA: &str = "outer_kernel_path";
const OUTER_KERNEL_SHA256_METADATA: &str = "outer_kernel_sha256";
const OUTER_INITRD_PATH_METADATA: &str = "outer_initrd_path";
const OUTER_INITRD_SHA256_METADATA: &str = "outer_initrd_sha256";
const PARENT_BUNDLE_DIR_METADATA: &str = "parent_bundle_dir";
const PARENT_BUNDLE_FINGERPRINT_METADATA: &str = "parent_bundle_fingerprint";
const PARENT_WORK_LAYOUT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedNitroBuildFlavor {
	StageX,
	LocalCrossCompile,
}

impl NestedNitroBuildFlavor {
	#[must_use]
	pub fn builder_kind(self) -> BuilderKind {
		match self {
			Self::StageX => BuilderKind::StageX,
			Self::LocalCrossCompile => BuilderKind::LocalCrossCompile,
		}
	}

	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::StageX => "stagex",
			Self::LocalCrossCompile => "cross",
		}
	}

	pub fn parse(value: &str) -> Result<Self, String> {
		match value {
			"stagex" | "StageX" | "STAGEX" => Ok(Self::StageX),
			"cross" | "local-cross" | "local_cross" | "LocalCrossCompile" => {
				Ok(Self::LocalCrossCompile)
			}
			_ => Err(format!(
				"invalid nested Nitro builder `{value}`; expected `stagex` or `cross`"
			)),
		}
	}
}

#[derive(Debug, Clone)]
pub struct NestedNitroQemuConfig {
	pub workspace_root: PathBuf,
	pub output_dir: PathBuf,
	pub build_flavor: NestedNitroBuildFlavor,
	pub outer_qemu_bin: PathBuf,
	pub outer_kernel_path: Option<PathBuf>,
	pub outer_initrd_path: Option<PathBuf>,
	pub outer_kernel_cmdline: String,
	pub outer_machine: String,
	pub outer_accel: Option<String>,
	pub outer_cpu: Option<String>,
	pub outer_net_device: String,
	pub host: String,
	pub app_host_port: u16,
	pub parent_control_port: u16,
	pub parent_app_port: u16,
	pub profile: BuildProfile,
	pub parent_target_triple: String,
	pub parent_target_linker: Option<String>,
	pub enclave_target_triple: String,
	pub enclave_target_linker: Option<String>,
	pub outer_memory: String,
	pub inner_memory: String,
	pub parent_bundle_dir: Option<PathBuf>,
	pub parent_qemu_path: String,
	pub parent_vhost_vsock_path: String,
	pub vhost_socket_path: String,
	pub inner_qemu_id: String,
	pub nested_guest_cid: u32,
	pub nested_forward_cid: u32,
	pub nested_core_port: u32,
	pub host_vsock_to_host: bool,
	pub bridge_vsock_to_host: bool,
	pub keep_on_failure: bool,
}

impl NestedNitroQemuConfig {
	#[must_use]
	pub fn new(workspace_root: impl Into<PathBuf>, app_host_port: u16) -> Self {
		let workspace_root = workspace_root.into();
		let output_dir =
			workspace_root.join("target/qos-test-harness/nested-nitro");

		Self {
			output_dir,
			workspace_root,
			build_flavor: NestedNitroBuildFlavor::StageX,
			outer_qemu_bin: PathBuf::from("qemu-system-x86_64"),
			outer_kernel_path: None,
			outer_initrd_path: None,
			outer_kernel_cmdline: DEFAULT_OUTER_KERNEL_CMDLINE.to_string(),
			outer_machine: "pc".to_string(),
			outer_accel: None,
			outer_cpu: None,
			outer_net_device: DEFAULT_OUTER_NET_DEVICE.to_string(),
			host: "127.0.0.1".to_string(),
			app_host_port,
			parent_control_port: DEFAULT_PARENT_CONTROL_PORT,
			parent_app_port: DEFAULT_PARENT_APP_PORT,
			profile: BuildProfile::Release,
			parent_target_triple: X86_64_LINUX_MUSL_TARGET.to_string(),
			parent_target_linker: Some("x86_64-linux-musl-gcc".to_string()),
			enclave_target_triple: X86_64_LINUX_MUSL_TARGET.to_string(),
			enclave_target_linker: Some("x86_64-linux-musl-gcc".to_string()),
			outer_memory: "6G".to_string(),
			inner_memory: "4G".to_string(),
			parent_bundle_dir: None,
			parent_qemu_path: DEFAULT_PARENT_QEMU_PATH.to_string(),
			parent_vhost_vsock_path: DEFAULT_PARENT_VHOST_VSOCK_PATH
				.to_string(),
			vhost_socket_path: DEFAULT_VHOST_SOCKET_PATH.to_string(),
			inner_qemu_id: DEFAULT_INNER_QEMU_ID.to_string(),
			nested_guest_cid: DEFAULT_NESTED_GUEST_CID,
			nested_forward_cid: DEFAULT_NESTED_FORWARD_CID,
			nested_core_port: DEFAULT_NESTED_CORE_PORT,
			host_vsock_to_host: false,
			bridge_vsock_to_host: false,
			keep_on_failure: false,
		}
	}

	fn validate_x86_only(&self) -> Result<(), String> {
		if self.parent_target_triple != X86_64_LINUX_MUSL_TARGET {
			return Err(format!(
				"nested Nitro parent target must be {X86_64_LINUX_MUSL_TARGET}, got {}",
				self.parent_target_triple
			));
		}
		if self.enclave_target_triple != X86_64_LINUX_MUSL_TARGET {
			return Err(format!(
				"nested Nitro enclave target must be {X86_64_LINUX_MUSL_TARGET}, got {}",
				self.enclave_target_triple
			));
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct NestedNitroQemuBuilder {
	config: NestedNitroQemuConfig,
}

impl NestedNitroQemuBuilder {
	#[must_use]
	pub fn new(config: NestedNitroQemuConfig) -> Self {
		Self { config }
	}

	fn record_path(&self, key: &BuildKey) -> PathBuf {
		self.config.output_dir.join(format!("{}.json", key.0))
	}

	fn parent_target_dir(&self) -> PathBuf {
		self.config.output_dir.join("parent-target")
	}

	fn enclave_target_dir(&self) -> PathBuf {
		self.config.output_dir.join("enclave-target")
	}

	fn eif_package_dir(&self) -> PathBuf {
		self.config.output_dir.join("eif-package")
	}

	fn parent_work_dir(&self) -> PathBuf {
		self.config.output_dir.join("parent-work-dir")
	}

	fn parent_binary_path(&self, bin: &str) -> PathBuf {
		self.parent_target_dir()
			.join(&self.config.parent_target_triple)
			.join(self.config.profile.target_dir_segment())
			.join(bin)
	}

	fn enclave_binary_path(&self, bin: &str) -> PathBuf {
		self.enclave_target_dir()
			.join(&self.config.enclave_target_triple)
			.join(self.config.profile.target_dir_segment())
			.join(bin)
	}

	fn build_parent_binary(
		&self,
		package: &str,
		bin: &str,
		features: &[&str],
		no_default_features: bool,
	) -> Result<BuildArtifact, BuildError> {
		let mut command = Command::new("cargo");
		command
			.arg("build")
			.arg("--locked")
			.arg("-p")
			.arg(package)
			.arg("--bin")
			.arg(bin)
			.arg("--target")
			.arg(&self.config.parent_target_triple)
			.arg("--target-dir")
			.arg(self.parent_target_dir())
			.current_dir(&self.config.workspace_root);
		if no_default_features {
			command.arg("--no-default-features");
		}
		for feature in features {
			command.arg("--features").arg(feature);
		}
		configure_target_linker(
			&mut command,
			&self.config.parent_target_triple,
			self.config.parent_target_linker.as_deref(),
		);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			command.arg(profile);
		}
		run_command(&mut command)?;

		artifact_for_path(&self.parent_binary_path(bin))
	}

	fn build_parent_binaries(&self) -> Result<Vec<HostBinary>, BuildError> {
		let mut binaries = Vec::new();
		for (package, bin, features, no_default_features) in [
			(
				"qos_test_harness",
				NESTED_PARENT_INIT_BIN,
				&["nested-parent-init"][..],
				false,
			),
			(QOS_HOST_BIN, QOS_HOST_BIN, &[][..], false),
			(QOS_CLIENT_BIN, QOS_CLIENT_BIN, &[][..], true),
			(QOS_BRIDGE_BIN, QOS_BRIDGE_BIN, &[][..], false),
		] {
			binaries.push(HostBinary {
				name: bin.to_string(),
				artifact: self.build_parent_binary(
					package,
					bin,
					features,
					no_default_features,
				)?,
			});
		}
		Ok(binaries)
	}

	fn build_pivot(&self) -> Result<BuildArtifact, BuildError> {
		let mut command = Command::new("cargo");
		command
			.arg("build")
			.arg("--locked")
			.arg("-p")
			.arg("qos_test_harness")
			.arg("--bin")
			.arg(SIGNED_ECHO_BIN)
			.arg("--target")
			.arg(&self.config.enclave_target_triple)
			.arg("--target-dir")
			.arg(self.enclave_target_dir())
			.current_dir(&self.config.workspace_root);
		configure_target_linker(
			&mut command,
			&self.config.enclave_target_triple,
			self.config.enclave_target_linker.as_deref(),
		);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			command.arg(profile);
		}
		run_command(&mut command)?;

		artifact_for_path(&self.enclave_binary_path(SIGNED_ECHO_BIN))
	}

	fn build_eif(&self, key: &BuildKey) -> Result<BuildArtifact, BuildError> {
		fs::create_dir_all(&self.config.output_dir)?;
		let tar_path = self.config.output_dir.join("nitro-eif.tar");
		let package_dir = self.eif_package_dir();
		if package_dir.exists() {
			fs::remove_dir_all(&package_dir)?;
		}
		fs::create_dir_all(&package_dir)?;

		let image_tag = format!("qos-qemu-nested-nitro:{}", key.0);
		run_command(
			Command::new("docker")
				.arg("build")
				.arg("-t")
				.arg(image_tag)
				.arg("-f")
				.arg(NESTED_NITRO_CONTAINERFILE)
				.arg(".")
				.arg("--output")
				.arg(format!("type=tar,dest={}", tar_path.display()))
				.current_dir(&self.config.workspace_root),
		)?;
		run_command(
			Command::new("tar")
				.arg("-xf")
				.arg(&tar_path)
				.arg("-C")
				.arg(&package_dir),
		)?;

		artifact_for_path(&package_dir.join("nitro.eif"))
	}

	fn stage_parent_work_dir(
		&self,
		host_binaries: &[HostBinary],
		pivot: &BuildArtifact,
		eif: &BuildArtifact,
	) -> Result<(), BuildError> {
		let work = self.parent_work_dir();
		if work.exists() {
			fs::remove_dir_all(&work)?;
		}
		fs::create_dir_all(&work)?;

		copy_executable(
			&find_host_binary(host_binaries, NESTED_PARENT_INIT_BIN)?.path,
			&work.join(NESTED_PARENT_INIT_BIN),
		)?;
		for name in [QOS_HOST_BIN, QOS_CLIENT_BIN, QOS_BRIDGE_BIN] {
			copy_executable(
				&find_host_binary(host_binaries, name)?.path,
				&work.join(name),
			)?;
		}
		copy_executable(&pivot.path, &work.join(SIGNED_ECHO_BIN))?;
		copy_executable(&eif.path, &work.join("nitro.eif"))?;
		Ok(())
	}

	fn parent_bundle_dir(&self) -> Result<PathBuf, BuildError> {
		let bundle =
			self.config.parent_bundle_dir.clone().ok_or_else(|| {
				BuildError::InvalidOutput(
					"nested Nitro QEMU requires parent_bundle_dir".to_string(),
				)
			})?;
		if !bundle.is_dir() {
			return Err(BuildError::MissingArtifact(
				bundle.display().to_string(),
			));
		}
		Ok(bundle)
	}

	fn parent_bundle_artifact(
		&self,
		name: &str,
	) -> Result<BuildArtifact, BuildError> {
		artifact_for_path(&self.parent_bundle_dir()?.join(name))
	}

	fn parent_bundle_fingerprint(&self) -> Result<String, BuildError> {
		directory_fingerprint(&self.parent_bundle_dir()?)
	}
}

impl ArtifactBuilder for NestedNitroQemuBuilder {
	fn build_key(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildKey, BuildError> {
		self.config.validate_x86_only().map_err(BuildError::InvalidOutput)?;
		let bundle_fingerprint = self.parent_bundle_fingerprint()?;
		let workspace = workspace_state(&plan.workspace_root);
		let raw = serde_json::json!({
			"workspace": workspace,
			"builder": self.config.build_flavor.builder_kind(),
			"nested_build_flavor": self.config.build_flavor.name(),
			"runner": plan.request.runner,
			"host_runner": plan.request.host_runner,
			"profile": plan.profile,
			"parent_target": self.config.parent_target_triple,
			"parent_target_linker": self.config.parent_target_linker,
			"enclave_target": self.config.enclave_target_triple,
			"enclave_target_linker": self.config.enclave_target_linker,
			"package": plan.package,
			"bin": plan.bin,
			"containerfile": NESTED_NITRO_CONTAINERFILE,
			"parent_work_layout_version": PARENT_WORK_LAYOUT_VERSION,
			"parent_bundle_dir": self.config.parent_bundle_dir,
			"parent_bundle_fingerprint": bundle_fingerprint,
			"outer_kernel_path": self.config.outer_kernel_path,
			"outer_initrd_path": self.config.outer_initrd_path,
			"outer_kernel_cmdline": self.config.outer_kernel_cmdline,
			"outer_machine": self.config.outer_machine,
			"outer_accel": self.config.outer_accel,
			"outer_cpu": self.config.outer_cpu,
			"outer_net_device": self.config.outer_net_device,
			"parent_qemu_path": self.config.parent_qemu_path,
			"parent_vhost_vsock_path": self.config.parent_vhost_vsock_path,
			"nested_guest_cid": self.config.nested_guest_cid,
			"nested_forward_cid": self.config.nested_forward_cid,
			"nested_core_port": self.config.nested_core_port,
			"parent_control_port": self.config.parent_control_port,
			"parent_app_port": self.config.parent_app_port,
			"extra": plan.extra_inputs,
		});
		Ok(BuildKey(sha256_hex(raw.to_string().as_bytes())))
	}

	async fn build(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildOutput, BuildError> {
		let key = self.build_key(plan)?;
		let record_path = self.record_path(&key);
		if let Ok(record) = read_build_record(&record_path)
			&& self.validate(&record.output).is_ok()
		{
			return Ok(record.output);
		}

		let host_binaries = self.build_parent_binaries()?;
		let pivot = self.build_pivot()?;
		let eif = self.build_eif(&key)?;
		self.stage_parent_work_dir(&host_binaries, &pivot, &eif)?;

		let mut metadata = BTreeMap::new();
		metadata.insert(
			"nested_build_flavor".to_string(),
			self.config.build_flavor.name().to_string(),
		);
		metadata.insert(
			PARENT_WORK_DIR_METADATA.to_string(),
			self.parent_work_dir().display().to_string(),
		);
		let root_image = self.parent_root_image_artifact()?;
		metadata.insert(
			PARENT_ROOT_IMAGE_PATH_METADATA.to_string(),
			root_image.path.display().to_string(),
		);
		metadata.insert(
			PARENT_ROOT_IMAGE_SHA256_METADATA.to_string(),
			root_image.sha256_hex.clone(),
		);
		let kernel = self.outer_kernel_artifact()?;
		metadata.insert(
			OUTER_KERNEL_PATH_METADATA.to_string(),
			kernel.path.display().to_string(),
		);
		metadata.insert(
			OUTER_KERNEL_SHA256_METADATA.to_string(),
			kernel.sha256_hex.clone(),
		);
		let initrd = self.outer_initrd_artifact()?;
		metadata.insert(
			OUTER_INITRD_PATH_METADATA.to_string(),
			initrd.path.display().to_string(),
		);
		metadata.insert(
			OUTER_INITRD_SHA256_METADATA.to_string(),
			initrd.sha256_hex.clone(),
		);
		let bundle = self.parent_bundle_dir()?;
		metadata.insert(
			PARENT_BUNDLE_DIR_METADATA.to_string(),
			bundle.display().to_string(),
		);
		metadata.insert(
			PARENT_BUNDLE_FINGERPRINT_METADATA.to_string(),
			self.parent_bundle_fingerprint()?,
		);

		let output = BuildOutput {
			key: key.clone(),
			builder: self.config.build_flavor.builder_kind(),
			runner: RunnerKind::NestedNitroQemu,
			host_runner: HostRunnerKind::Qemu,
			workspace: workspace_state(&plan.workspace_root),
			pivot: Some(pivot),
			host_binaries,
			enclave_binaries: Vec::new(),
			image_ref: None,
			image_id: None,
			eif: Some(eif),
			rootfs: None,
			metadata,
		};
		self.validate(&output)?;
		write_build_record(
			&record_path,
			&BuildRecord { output: output.clone() },
		)?;
		Ok(output)
	}

	fn validate(&self, output: &BuildOutput) -> Result<(), BuildError> {
		let pivot = output
			.pivot
			.as_ref()
			.ok_or_else(|| BuildError::MissingArtifact("pivot".into()))?;
		validate_artifact(pivot)?;
		let eif = output
			.eif
			.as_ref()
			.ok_or_else(|| BuildError::MissingArtifact("eif".into()))?;
		validate_artifact(eif)?;
		for host_binary in &output.host_binaries {
			validate_artifact(&host_binary.artifact)?;
		}
		let work_dir =
			output.metadata.get(PARENT_WORK_DIR_METADATA).ok_or_else(|| {
				BuildError::MissingArtifact(
					PARENT_WORK_DIR_METADATA.to_string(),
				)
			})?;
		let work_dir = PathBuf::from(work_dir);
		if !work_dir.is_dir() {
			return Err(BuildError::MissingArtifact(
				work_dir.display().to_string(),
			));
		}
		for staged_name in [
			NESTED_PARENT_INIT_BIN,
			QOS_HOST_BIN,
			QOS_CLIENT_BIN,
			QOS_BRIDGE_BIN,
			SIGNED_ECHO_BIN,
			"nitro.eif",
		] {
			let staged = work_dir.join(staged_name);
			validate_path_exists(&staged)?;
		}
		let root_image = metadata_artifact(
			output,
			PARENT_ROOT_IMAGE_PATH_METADATA,
			PARENT_ROOT_IMAGE_SHA256_METADATA,
		)?;
		validate_artifact(&root_image)?;
		let kernel_path = output
			.metadata
			.get(OUTER_KERNEL_PATH_METADATA)
			.ok_or_else(|| {
				BuildError::MissingArtifact(
					OUTER_KERNEL_PATH_METADATA.to_string(),
				)
			})?;
		let kernel = BuildArtifact {
			path: PathBuf::from(kernel_path),
			sha256_hex: output
				.metadata
				.get(OUTER_KERNEL_SHA256_METADATA)
				.cloned()
				.ok_or_else(|| {
					BuildError::MissingArtifact(
						OUTER_KERNEL_SHA256_METADATA.to_string(),
					)
				})?,
		};
		validate_artifact(&kernel)?;
		let initrd = metadata_artifact(
			output,
			OUTER_INITRD_PATH_METADATA,
			OUTER_INITRD_SHA256_METADATA,
		)?;
		validate_artifact(&initrd)
	}
}

impl NestedNitroQemuBuilder {
	fn parent_root_image_artifact(&self) -> Result<BuildArtifact, BuildError> {
		self.parent_bundle_artifact("rootfs.ext4")
	}

	fn outer_kernel_artifact(&self) -> Result<BuildArtifact, BuildError> {
		if let Some(kernel) = self.config.outer_kernel_path.as_ref() {
			return artifact_for_path(kernel);
		}
		self.parent_bundle_artifact("vmlinuz")
	}

	fn outer_initrd_artifact(&self) -> Result<BuildArtifact, BuildError> {
		if let Some(initrd) = self.config.outer_initrd_path.as_ref() {
			return artifact_for_path(initrd);
		}
		self.parent_bundle_artifact("initramfs.img")
	}
}

#[derive(Debug)]
pub struct NestedNitroQemuRunner {
	config: NestedNitroQemuConfig,
	builder: NestedNitroQemuBuilder,
	build_output: Option<BuildOutput>,
	children: Vec<ManagedChild>,
}

impl NestedNitroQemuRunner {
	#[must_use]
	pub fn new(config: NestedNitroQemuConfig) -> Self {
		let builder = NestedNitroQemuBuilder::new(config.clone());
		Self { config, builder, build_output: None, children: Vec::new() }
	}

	pub fn preflight(&self) -> Result<(), RunnerError> {
		self.config.validate_x86_only().map_err(RunnerError::new)?;
		command_exists(&self.config.outer_qemu_bin)?;
		if let Some(linker) = self.config.parent_target_linker.as_ref() {
			command_exists(Path::new(linker))?;
		}
		if let Some(linker) = self.config.enclave_target_linker.as_ref() {
			command_exists(Path::new(linker))?;
		}
		let bundle = self.config.parent_bundle_dir.as_ref().ok_or_else(|| {
			RunnerError::new(
				"set QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE to a Rawhide parent bundle; build one with ./src/qos_test_harness/scripts/build_nested_nitro_rawhide_parent.sh",
			)
		})?;
		if !bundle.is_dir() {
			return Err(RunnerError::new(format!(
				"parent bundle does not exist: {}",
				bundle.display()
			)));
		}
		for file in ["rootfs.ext4", "vmlinuz", "initramfs.img"] {
			let path = bundle.join(file);
			if !path.exists() {
				return Err(RunnerError::new(format!(
					"parent bundle missing {} at {}",
					file,
					path.display()
				)));
			}
		}
		for path in [
			self.config.outer_kernel_path.as_ref(),
			self.config.outer_initrd_path.as_ref(),
		]
		.into_iter()
		.flatten()
		{
			if !path.exists() {
				return Err(RunnerError::new(format!(
					"outer boot artifact does not exist: {}",
					path.display()
				)));
			}
		}
		run_command(Command::new("docker").arg("info"))
			.map(|_| ())
			.map_err(RunnerError::from)
	}

	fn build_plan(&self, request: ArtifactRequest) -> ArtifactBuildPlan {
		ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: request,
				runner: RunnerKind::NestedNitroQemu,
				host_runner: HostRunnerKind::Qemu,
			},
			workspace_root: self.config.workspace_root.clone(),
			output_dir: self.config.output_dir.clone(),
			builder: self.config.build_flavor.builder_kind(),
			profile: self.config.profile.clone(),
			target_triple: Some(self.config.enclave_target_triple.clone()),
			package: "qos_test_harness".to_string(),
			bin: SIGNED_ECHO_BIN.to_string(),
			extra_inputs: BTreeMap::new(),
		}
	}

	fn endpoint(&self) -> AppEndpoint {
		let base_url = format!(
			"http://{}:{}",
			self.config.host, self.config.app_host_port
		);
		AppEndpoint {
			base_url: Some(base_url.clone()),
			health_url: format!("{base_url}/health"),
			signed_echo_url: format!("{base_url}/echo"),
			metadata: BTreeMap::new(),
		}
	}

	fn start_app_inner(
		&mut self,
		spec: StartAppSpec,
	) -> Result<RunningApp, RunnerError> {
		self.verify_app_artifact(&spec.artifact)?;
		let run_id = timestamp_millis();
		let run_dir =
			self.config.output_dir.join("run").join(run_id.to_string());
		fs::create_dir_all(&run_dir).map_err(io_error)?;
		self.write_parent_config(&spec)?;
		self.start_outer_qemu(&run_dir)?;

		let mut metadata = BTreeMap::new();
		metadata.insert("run_dir".to_string(), run_dir.display().to_string());
		metadata.insert("runner".to_string(), "nested_nitro_qemu".to_string());
		metadata.insert(
			"host_runner".to_string(),
			format!("{:?}", HostRunnerKind::Qemu),
		);
		metadata.insert(
			"outer_kernel".to_string(),
			self.outer_kernel_for_start()?.display().to_string(),
		);
		metadata.insert(
			"outer_initrd".to_string(),
			self.outer_initrd_for_start()?.display().to_string(),
		);
		metadata.insert(
			"parent_root_image".to_string(),
			self.parent_root_image_for_start()?.display().to_string(),
		);
		metadata.insert(
			"parent_work_dir".to_string(),
			self.parent_work_dir_for_start()?.display().to_string(),
		);
		Ok(RunningApp { id: run_id.to_string(), metadata })
	}

	fn verify_app_artifact(
		&self,
		artifact: &AppArtifact,
	) -> Result<(), RunnerError> {
		let AppArtifact::LocalBinary { path, sha256_hex } = artifact else {
			return Err(RunnerError::new(
				"nested Nitro QEMU runner requires a local pivot binary",
			));
		};
		if let Some(expected) = sha256_hex {
			let actual = sha256_file_hex(path).map_err(RunnerError::from)?;
			if actual != *expected {
				return Err(RunnerError::new(format!(
					"pivot hash mismatch for {}: expected {expected}, actual {actual}",
					path.display()
				)));
			}
		}
		Ok(())
	}

	fn write_parent_config(
		&self,
		spec: &StartAppSpec,
	) -> Result<(), RunnerError> {
		let work = self.parent_work_dir_for_start()?;
		let config_path = work.join("nested-parent.env");
		let mut file = File::create(&config_path).map_err(io_error)?;
		let pivot_args = encode_pivot_args(&spec.pivot_args)?;
		let bridge_config = format!(
			"[{{\"type\":\"server\",\"port\":{},\"host\":\"0.0.0.0\"}}]",
			self.config.parent_app_port
		);
		for (key, value) in [
			(
				"VHOST_DEVICE_VSOCK",
				self.config.parent_vhost_vsock_path.as_str(),
			),
			("VHOST_SOCKET", self.config.vhost_socket_path.as_str()),
			("INNER_QEMU", self.config.parent_qemu_path.as_str()),
			("INNER_EIF", "/work/nitro.eif"),
			("INNER_QEMU_ID", self.config.inner_qemu_id.as_str()),
			("INNER_QEMU_MEMORY", self.config.inner_memory.as_str()),
			("INNER_QEMU_ENABLE_KVM", "false"),
			("QOS_HOST", "/work/qos_host"),
			("QOS_CLIENT", "/work/qos_client"),
			("QOS_BRIDGE", "/work/qos_bridge"),
			("QOS_PARENT_HOST", "0.0.0.0"),
			("QOS_PARENT_CONTROL_HOST", "127.0.0.1"),
			("PIVOT_PATH", "/work/signed_echo"),
			("RESTART_POLICY", "never"),
		] {
			write_config_line(&mut file, key, value)?;
		}
		for (key, value) in [
			(
				"QOS_PARENT_CONTROL_PORT",
				self.config.parent_control_port.to_string(),
			),
			("QOS_PARENT_APP_PORT", self.config.parent_app_port.to_string()),
			("NESTED_GUEST_CID", self.config.nested_guest_cid.to_string()),
			("NESTED_FORWARD_CID", self.config.nested_forward_cid.to_string()),
			("NESTED_CORE_PORT", self.config.nested_core_port.to_string()),
			(
				"VHOST_FORWARD_LISTEN",
				format!(
					"{}+{}",
					self.config.nested_core_port, self.config.parent_app_port
				),
			),
			("PIVOT_ARGS", pivot_args),
			("BRIDGE_CONFIG", bridge_config),
			(
				"QOS_HOST_VSOCK_TO_HOST",
				self.config.host_vsock_to_host.to_string(),
			),
			(
				"QOS_BRIDGE_VSOCK_TO_HOST",
				self.config.bridge_vsock_to_host.to_string(),
			),
		] {
			write_config_line(&mut file, key, &value)?;
		}
		Ok(())
	}

	fn start_outer_qemu(&mut self, run_dir: &Path) -> Result<(), RunnerError> {
		let kernel = self.outer_kernel_for_start()?;
		let initrd = self.outer_initrd_for_start()?;
		let root_image = self.parent_root_image_for_start()?;
		let work_dir = self.parent_work_dir_for_start()?;
		let mut command = Command::new(&self.config.outer_qemu_bin);
		command
			.arg("-machine")
			.arg(&self.config.outer_machine)
			.arg("-kernel")
			.arg(&kernel)
			.arg("-initrd")
			.arg(&initrd)
			.arg("-append")
			.arg(&self.config.outer_kernel_cmdline)
			.arg("-nographic")
			.arg("-m")
			.arg(&self.config.outer_memory)
			.arg("-netdev")
			.arg(format!(
				"user,id=parentnet,hostfwd=tcp:{}:{}-:{}",
				self.config.host,
				self.config.app_host_port,
				self.config.parent_app_port
			))
			.arg("-device")
			.arg(&self.config.outer_net_device)
			.arg("-drive")
			.arg(format!(
				"file={},format=raw,if=virtio,snapshot=on",
				root_image.display()
			))
			.arg("-virtfs")
			.arg(format!(
				"local,path={},mount_tag=qoswork,security_model=none",
				work_dir.display()
			));
		if let Some(accel) = self.config.outer_accel.as_ref() {
			command.arg("-accel").arg(accel);
		}
		if let Some(cpu) = self.config.outer_cpu.as_ref() {
			command.arg("-cpu").arg(cpu);
		}
		let child = spawn_logged("qemu-nested-parent", &mut command, run_dir)?;
		self.children.push(child);
		Ok(())
	}

	fn outer_kernel_for_start(&self) -> Result<PathBuf, RunnerError> {
		if let Some(kernel) = self.config.outer_kernel_path.as_ref() {
			return Ok(kernel.clone());
		}
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path = output.metadata.get(OUTER_KERNEL_PATH_METADATA).ok_or_else(
			|| {
				RunnerError::new(
					"nested Nitro builder returned no outer kernel",
				)
			},
		)?;
		Ok(PathBuf::from(path))
	}

	fn outer_initrd_for_start(&self) -> Result<PathBuf, RunnerError> {
		if let Some(initrd) = self.config.outer_initrd_path.as_ref() {
			return Ok(initrd.clone());
		}
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path = output.metadata.get(OUTER_INITRD_PATH_METADATA).ok_or_else(
			|| {
				RunnerError::new(
					"nested Nitro builder returned no outer initrd",
				)
			},
		)?;
		Ok(PathBuf::from(path))
	}

	fn parent_root_image_for_start(&self) -> Result<PathBuf, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path = output
			.metadata
			.get(PARENT_ROOT_IMAGE_PATH_METADATA)
			.ok_or_else(|| {
				RunnerError::new(
					"nested Nitro builder returned no parent root image",
				)
			})?;
		Ok(PathBuf::from(path))
	}

	fn parent_work_dir_for_start(&self) -> Result<PathBuf, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path =
			output.metadata.get(PARENT_WORK_DIR_METADATA).ok_or_else(|| {
				RunnerError::new(
					"nested Nitro builder returned no parent work dir",
				)
			})?;
		let path = PathBuf::from(path);
		if !path.is_dir() {
			return Err(RunnerError::new(format!(
				"parent work dir does not exist: {}",
				path.display()
			)));
		}
		Ok(path)
	}

	fn stop_children(&mut self, keep: bool) -> Result<(), RunnerError> {
		if keep {
			return Ok(());
		}

		let mut errors = Vec::new();
		for child in self.children.iter_mut().rev() {
			if let Err(err) = child.stop() {
				errors.push(err);
			}
		}
		self.children.clear();

		if errors.is_empty() {
			Ok(())
		} else {
			Err(RunnerError::new(errors.join("; ")))
		}
	}
}

impl TestRunner for NestedNitroQemuRunner {
	async fn prepare_artifact(
		&mut self,
		request: ArtifactRequest,
	) -> Result<AppArtifact, RunnerError> {
		self.preflight()?;
		let output = self.builder.build(&self.build_plan(request)).await?;
		let pivot = output.pivot.clone().ok_or_else(|| {
			RunnerError::new("nested Nitro builder returned no pivot")
		})?;
		self.build_output = Some(output);
		Ok(AppArtifact::LocalBinary {
			path: pivot.path,
			sha256_hex: Some(pivot.sha256_hex),
		})
	}

	async fn start_app(
		&mut self,
		spec: StartAppSpec,
	) -> Result<RunningApp, RunnerError> {
		match self.start_app_inner(spec) {
			Ok(app) => Ok(app),
			Err(err) => {
				let _ = self.stop_children(false);
				Err(err)
			}
		}
	}

	async fn wait_ready(
		&mut self,
		_app: &RunningApp,
		timeout: Duration,
	) -> Result<AppEndpoint, RunnerError> {
		let endpoint = self.endpoint();
		wait_for_http_ok(&endpoint.health_url, timeout, &mut self.children)?;
		Ok(endpoint)
	}

	async fn http_get(
		&mut self,
		url: &str,
	) -> Result<HttpResponse, RunnerError> {
		http_get(url).map_err(RunnerError::from)
	}

	async fn http_post(
		&mut self,
		url: &str,
		body: &[u8],
	) -> Result<HttpResponse, RunnerError> {
		http_post(url, body).map_err(RunnerError::from)
	}

	async fn stop_app(
		&mut self,
		_app: RunningApp,
		outcome: TestOutcome,
	) -> Result<(), RunnerError> {
		let keep = self.config.keep_on_failure
			&& matches!(outcome, TestOutcome::Failed { .. });
		self.stop_children(keep)
	}
}

fn artifact_for_path(path: &Path) -> Result<BuildArtifact, BuildError> {
	if !path.exists() {
		return Err(BuildError::MissingArtifact(path.display().to_string()));
	}
	Ok(BuildArtifact { sha256_hex: sha256_file_hex(path)?, path: path.into() })
}

fn metadata_artifact(
	output: &BuildOutput,
	path_key: &str,
	sha256_key: &str,
) -> Result<BuildArtifact, BuildError> {
	let path = output
		.metadata
		.get(path_key)
		.ok_or_else(|| BuildError::MissingArtifact(path_key.to_string()))?;
	let sha256_hex =
		output.metadata.get(sha256_key).cloned().ok_or_else(|| {
			BuildError::MissingArtifact(sha256_key.to_string())
		})?;
	Ok(BuildArtifact { path: PathBuf::from(path), sha256_hex })
}

fn validate_path_exists(path: &Path) -> Result<(), BuildError> {
	if !path.exists() {
		return Err(BuildError::MissingArtifact(path.display().to_string()));
	}
	Ok(())
}

fn validate_artifact(artifact: &BuildArtifact) -> Result<(), BuildError> {
	if !artifact.path.exists() {
		return Err(BuildError::MissingArtifact(
			artifact.path.display().to_string(),
		));
	}
	let actual = sha256_file_hex(&artifact.path)?;
	if actual != artifact.sha256_hex {
		return Err(BuildError::InvalidOutput(format!(
			"hash mismatch for {}: expected {} actual {actual}",
			artifact.path.display(),
			artifact.sha256_hex
		)));
	}
	Ok(())
}

fn configure_target_linker(
	command: &mut Command,
	target_triple: &str,
	linker: Option<&str>,
) {
	let Some(linker) = linker else {
		return;
	};
	let env_key = format!(
		"CARGO_TARGET_{}_LINKER",
		target_triple.replace('-', "_").to_ascii_uppercase()
	);
	command.env(env_key, linker);
}

fn find_host_binary<'a>(
	binaries: &'a [HostBinary],
	name: &str,
) -> Result<&'a BuildArtifact, BuildError> {
	binaries
		.iter()
		.find(|binary| binary.name == name)
		.map(|binary| &binary.artifact)
		.ok_or_else(|| {
			BuildError::MissingArtifact(format!("host binary `{name}`"))
		})
}

fn copy_executable(source: &Path, dest: &Path) -> Result<(), BuildError> {
	if let Some(parent) = dest.parent() {
		fs::create_dir_all(parent)?;
	}
	fs::copy(source, dest)?;
	fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
	Ok(())
}

fn directory_fingerprint(root: &Path) -> Result<String, BuildError> {
	let mut lines = Vec::new();
	fingerprint_path(root, root, &mut lines)?;
	lines.sort();
	Ok(sha256_hex(lines.join("\n").as_bytes()))
}

fn fingerprint_path(
	root: &Path,
	path: &Path,
	lines: &mut Vec<String>,
) -> Result<(), BuildError> {
	let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
	entries.sort_by_key(|entry| entry.path());
	for entry in entries {
		let entry_path = entry.path();
		let relative = entry_path
			.strip_prefix(root)
			.unwrap_or(&entry_path)
			.display()
			.to_string();
		let metadata = fs::symlink_metadata(&entry_path)?;
		if metadata.is_dir() {
			lines.push(format!("dir {relative}"));
			fingerprint_path(root, &entry_path, lines)?;
		} else if metadata.is_file() {
			lines.push(format!(
				"file {relative} {} {}",
				metadata.len(),
				sha256_file_hex(&entry_path)?
			));
		} else if metadata.file_type().is_symlink() {
			lines.push(format!(
				"symlink {relative} {}",
				fs::read_link(&entry_path)?.display()
			));
		}
	}
	Ok(())
}

fn write_config_line(
	file: &mut File,
	key: &str,
	value: &str,
) -> Result<(), RunnerError> {
	if value.contains('\n') {
		return Err(RunnerError::new(format!(
			"config value for {key} contains a newline"
		)));
	}
	writeln!(file, "{key}={value}").map_err(io_error)
}

fn encode_pivot_args(args: &[String]) -> Result<String, RunnerError> {
	for arg in args {
		if arg.contains([',', '[', ']']) {
			return Err(RunnerError::new(format!(
				"pivot arg `{arg}` cannot be represented by qos_client's comma-separated --pivot-args format"
			)));
		}
	}
	Ok(format!("[{}]", args.join(",")))
}

#[derive(Debug)]
struct ManagedChild {
	name: String,
	child: Child,
}

impl ManagedChild {
	fn stop(&mut self) -> Result<(), String> {
		match self.child.try_wait() {
			Ok(Some(_)) => return Ok(()),
			Ok(None) => {}
			Err(err) => {
				return Err(format!(
					"{} status check failed: {err}",
					self.name
				));
			}
		}

		self.child
			.kill()
			.map_err(|err| format!("{} kill failed: {err}", self.name))?;
		self.child
			.wait()
			.map(|_| ())
			.map_err(|err| format!("{} wait failed: {err}", self.name))
	}

	fn exited(&mut self) -> Result<Option<String>, RunnerError> {
		match self.child.try_wait().map_err(io_error)? {
			Some(status) => {
				Ok(Some(format!("{} exited with {status}", self.name)))
			}
			None => Ok(None),
		}
	}
}

fn spawn_logged(
	name: &str,
	command: &mut Command,
	run_dir: &Path,
) -> Result<ManagedChild, RunnerError> {
	let logs_dir = run_dir.join("logs");
	fs::create_dir_all(&logs_dir).map_err(io_error)?;
	let stdout = File::create(logs_dir.join(format!("{name}.stdout.log")))
		.map_err(io_error)?;
	let stderr = File::create(logs_dir.join(format!("{name}.stderr.log")))
		.map_err(io_error)?;
	let child = command
		.stdout(Stdio::from(stdout))
		.stderr(Stdio::from(stderr))
		.spawn()
		.map_err(|err| {
			RunnerError::new(format!("failed to spawn {name}: {err}"))
		})?;
	Ok(ManagedChild { name: name.to_string(), child })
}

fn wait_for_http_ok(
	url: &str,
	timeout: Duration,
	children: &mut [ManagedChild],
) -> Result<(), RunnerError> {
	let start = Instant::now();
	while start.elapsed() < timeout {
		fail_if_child_exited(children)?;
		if let Ok(response) = http_get(url)
			&& response.status == 200
		{
			return Ok(());
		}
		thread::sleep(Duration::from_millis(250));
	}
	Err(RunnerError::new(format!("timed out waiting for {url}")))
}

fn fail_if_child_exited(
	children: &mut [ManagedChild],
) -> Result<(), RunnerError> {
	for child in children {
		if let Some(message) = child.exited()? {
			return Err(RunnerError::new(message));
		}
	}
	Ok(())
}

fn command_exists(path: &Path) -> Result<(), RunnerError> {
	let status =
		Command::new(path).arg("--version").output().map_err(|err| {
			RunnerError::new(format!(
				"{} is required but could not be executed: {err}",
				path.display()
			))
		})?;
	if status.status.success() {
		Ok(())
	} else {
		Err(RunnerError::new(format!(
			"{} --version failed with {}",
			path.display(),
			status.status
		)))
	}
}

fn timestamp_millis() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system clock before unix epoch")
		.as_millis()
}

fn io_error(err: std::io::Error) -> RunnerError {
	RunnerError::new(err.to_string())
}
