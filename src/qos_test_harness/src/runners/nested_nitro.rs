use std::{
	collections::BTreeMap,
	fs::{self, File},
	io::Write,
	os::unix::fs::{PermissionsExt, symlink},
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
const DEFAULT_PARENT_CONTROL_PORT: u16 = 3001;
const DEFAULT_PARENT_APP_PORT: u16 = 3000;
const DEFAULT_NESTED_GUEST_CID: u32 = 4;
const DEFAULT_NESTED_FORWARD_CID: u32 = 1;
const DEFAULT_NESTED_CORE_PORT: u32 = 3;
const DEFAULT_OUTER_KERNEL_CMDLINE: &str = "console=ttyAMA0 panic=1 reboot=k root=qosparent rootfstype=9p rootflags=trans=virtio,version=9p2000.L rw init=/init";
const DEFAULT_OUTER_NET_DEVICE: &str = "virtio-net-pci,netdev=parentnet";
const DEFAULT_PARENT_QEMU_PATH: &str = "/tools/qemu-system-x86_64";
const DEFAULT_PARENT_VHOST_VSOCK_PATH: &str = "/tools/vhost-device-vsock";
const DEFAULT_VHOST_SOCKET_PATH: &str = "/tmp/qos-nitro-vhost.socket";
const DEFAULT_INNER_QEMU_ID: &str = "qos-test-harness";
const NESTED_NITRO_CONTAINERFILE: &str = "Containerfile.qemu";
const PARENT_ROOTFS_DIR_METADATA: &str = "parent_rootfs_dir";
const OUTER_KERNEL_PATH_METADATA: &str = "outer_kernel_path";
const OUTER_KERNEL_SHA256_METADATA: &str = "outer_kernel_sha256";
const PARENT_OVERLAY_DIR_METADATA: &str = "parent_overlay_dir";
const PARENT_OVERLAY_FINGERPRINT_METADATA: &str = "parent_overlay_fingerprint";
const PARENT_ROOTFS_LAYOUT_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct NestedNitroQemuConfig {
	pub workspace_root: PathBuf,
	pub output_dir: PathBuf,
	pub outer_qemu_bin: PathBuf,
	pub outer_kernel_path: Option<PathBuf>,
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
	pub parent_overlay_dir: Option<PathBuf>,
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
		let (outer_accel, outer_cpu) =
			if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
				(Some("hvf".to_string()), Some("host".to_string()))
			} else {
				(None, None)
			};

		Self {
			output_dir,
			workspace_root,
			outer_qemu_bin: PathBuf::from("qemu-system-aarch64"),
			outer_kernel_path: None,
			outer_kernel_cmdline: DEFAULT_OUTER_KERNEL_CMDLINE.to_string(),
			outer_machine: "virt".to_string(),
			outer_accel,
			outer_cpu,
			outer_net_device: DEFAULT_OUTER_NET_DEVICE.to_string(),
			host: "127.0.0.1".to_string(),
			app_host_port,
			parent_control_port: DEFAULT_PARENT_CONTROL_PORT,
			parent_app_port: DEFAULT_PARENT_APP_PORT,
			profile: BuildProfile::Release,
			parent_target_triple: "aarch64-unknown-linux-musl".to_string(),
			parent_target_linker: Some("aarch64-linux-musl-gcc".to_string()),
			enclave_target_triple: "x86_64-unknown-linux-musl".to_string(),
			enclave_target_linker: Some("x86_64-linux-musl-gcc".to_string()),
			outer_memory: "6G".to_string(),
			inner_memory: "4G".to_string(),
			parent_overlay_dir: None,
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

	fn parent_rootfs_dir(&self) -> PathBuf {
		self.config.output_dir.join("parent-rootfs-dir")
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
		for (package, bin, features) in [
			(
				"qos_test_harness",
				NESTED_PARENT_INIT_BIN,
				&["nested-parent-init"][..],
			),
			(QOS_HOST_BIN, QOS_HOST_BIN, &[][..]),
			(QOS_CLIENT_BIN, QOS_CLIENT_BIN, &[][..]),
			(QOS_BRIDGE_BIN, QOS_BRIDGE_BIN, &[][..]),
		] {
			binaries.push(HostBinary {
				name: bin.to_string(),
				artifact: self.build_parent_binary(package, bin, features)?,
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

	fn stage_parent_rootfs(
		&self,
		host_binaries: &[HostBinary],
		pivot: &BuildArtifact,
		eif: &BuildArtifact,
	) -> Result<(), BuildError> {
		let root = self.parent_rootfs_dir();
		if root.exists() {
			fs::remove_dir_all(&root)?;
		}
		fs::create_dir_all(&root)?;

		let overlay = self.parent_overlay_dir()?;
		copy_tree(&overlay, &root)?;

		for dir in [
			"dev",
			"proc",
			"sys",
			"tmp",
			"run",
			"work",
			"dev/pts",
			"dev/shm",
			"sys/fs/cgroup",
		] {
			fs::create_dir_all(root.join(dir))?;
		}
		fs::set_permissions(
			root.join("tmp"),
			fs::Permissions::from_mode(0o1777),
		)?;
		File::create(root.join("dev/null"))?;
		fs::set_permissions(
			root.join("dev/null"),
			fs::Permissions::from_mode(0o666),
		)?;

		copy_executable(
			&find_host_binary(host_binaries, NESTED_PARENT_INIT_BIN)?.path,
			&root.join("init"),
		)?;
		for name in [QOS_HOST_BIN, QOS_CLIENT_BIN, QOS_BRIDGE_BIN] {
			copy_executable(
				&find_host_binary(host_binaries, name)?.path,
				&root.join("work").join(name),
			)?;
		}
		copy_executable(&pivot.path, &root.join("work").join(SIGNED_ECHO_BIN))?;
		copy_executable(&eif.path, &root.join("work/nitro.eif"))?;
		Ok(())
	}

	fn parent_overlay_dir(&self) -> Result<PathBuf, BuildError> {
		let overlay =
			self.config.parent_overlay_dir.clone().ok_or_else(|| {
				BuildError::InvalidOutput(
					"nested Nitro QEMU requires parent_overlay_dir".to_string(),
				)
			})?;
		if !overlay.is_dir() {
			return Err(BuildError::MissingArtifact(
				overlay.display().to_string(),
			));
		}
		Ok(overlay)
	}

	fn overlay_fingerprint(&self) -> Result<String, BuildError> {
		directory_fingerprint(&self.parent_overlay_dir()?)
	}
}

impl ArtifactBuilder for NestedNitroQemuBuilder {
	fn build_key(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildKey, BuildError> {
		let overlay_fingerprint = self.overlay_fingerprint()?;
		let workspace = workspace_state(&plan.workspace_root);
		let raw = serde_json::json!({
			"workspace": workspace,
			"builder": plan.builder,
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
			"parent_rootfs_layout_version": PARENT_ROOTFS_LAYOUT_VERSION,
			"parent_overlay_dir": self.config.parent_overlay_dir,
			"parent_overlay_fingerprint": overlay_fingerprint,
			"outer_kernel_path": self.config.outer_kernel_path,
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
		self.stage_parent_rootfs(&host_binaries, &pivot, &eif)?;

		let mut metadata = BTreeMap::new();
		metadata.insert(
			PARENT_ROOTFS_DIR_METADATA.to_string(),
			self.parent_rootfs_dir().display().to_string(),
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
		let overlay = self.parent_overlay_dir()?;
		metadata.insert(
			PARENT_OVERLAY_DIR_METADATA.to_string(),
			overlay.display().to_string(),
		);
		metadata.insert(
			PARENT_OVERLAY_FINGERPRINT_METADATA.to_string(),
			self.overlay_fingerprint()?,
		);

		let output = BuildOutput {
			key: key.clone(),
			builder: BuilderKind::StageX,
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
		let rootfs_dir = output
			.metadata
			.get(PARENT_ROOTFS_DIR_METADATA)
			.ok_or_else(|| {
				BuildError::MissingArtifact(
					PARENT_ROOTFS_DIR_METADATA.to_string(),
				)
			})?;
		let rootfs_dir = PathBuf::from(rootfs_dir);
		if !rootfs_dir.is_dir() {
			return Err(BuildError::MissingArtifact(
				rootfs_dir.display().to_string(),
			));
		}
		for tool_path in [
			&self.config.parent_qemu_path,
			&self.config.parent_vhost_vsock_path,
		] {
			let staged = rootfs_dir.join(tool_path.trim_start_matches('/'));
			if !staged.exists() {
				return Err(BuildError::MissingArtifact(
					staged.display().to_string(),
				));
			}
		}
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
		validate_artifact(&kernel)
	}
}

impl NestedNitroQemuBuilder {
	fn outer_kernel_artifact(&self) -> Result<BuildArtifact, BuildError> {
		let kernel =
			self.config.outer_kernel_path.as_ref().ok_or_else(|| {
				BuildError::MissingArtifact(
					"outer_kernel_path for nested Nitro QEMU".to_string(),
				)
			})?;
		artifact_for_path(kernel)
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
		command_exists(&self.config.outer_qemu_bin)?;
		if let Some(linker) = self.config.parent_target_linker.as_ref() {
			command_exists(Path::new(linker))?;
		}
		if let Some(linker) = self.config.enclave_target_linker.as_ref() {
			command_exists(Path::new(linker))?;
		}
		let kernel = self.config.outer_kernel_path.as_ref().ok_or_else(|| {
			RunnerError::new(
				"set QOS_TEST_QEMU_NESTED_NITRO_OUTER_KERNEL for the parent Linux VM kernel",
			)
		})?;
		if !kernel.exists() {
			return Err(RunnerError::new(format!(
				"outer kernel does not exist: {}",
				kernel.display()
			)));
		}
		let overlay = self.config.parent_overlay_dir.as_ref().ok_or_else(|| {
			RunnerError::new(
				"set QOS_TEST_QEMU_NESTED_NITRO_PARENT_OVERLAY to a Linux/aarch64 rootfs overlay containing qemu-system-x86_64 and vhost-device-vsock",
			)
		})?;
		if !overlay.is_dir() {
			return Err(RunnerError::new(format!(
				"parent overlay does not exist: {}",
				overlay.display()
			)));
		}
		for tool_path in [
			&self.config.parent_qemu_path,
			&self.config.parent_vhost_vsock_path,
		] {
			let overlay_tool = overlay.join(tool_path.trim_start_matches('/'));
			if !overlay_tool.exists() {
				return Err(RunnerError::new(format!(
					"parent overlay missing {} at {}",
					tool_path,
					overlay_tool.display()
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
			builder: BuilderKind::StageX,
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
			"parent_rootfs_dir".to_string(),
			self.parent_rootfs_dir_for_start()?.display().to_string(),
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
		let rootfs = self.parent_rootfs_dir_for_start()?;
		let config_path = rootfs.join("work/nested-parent.env");
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
		let rootfs_dir = self.parent_rootfs_dir_for_start()?;
		let mut command = Command::new(&self.config.outer_qemu_bin);
		command
			.arg("-machine")
			.arg(&self.config.outer_machine)
			.arg("-kernel")
			.arg(&kernel)
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
			.arg("-virtfs")
			.arg(format!(
				"local,path={},mount_tag=qosparent,security_model=none",
				rootfs_dir.display()
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

	fn parent_rootfs_dir_for_start(&self) -> Result<PathBuf, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path = output.metadata.get(PARENT_ROOTFS_DIR_METADATA).ok_or_else(
			|| {
				RunnerError::new(
					"nested Nitro builder returned no parent rootfs dir",
				)
			},
		)?;
		let path = PathBuf::from(path);
		if !path.is_dir() {
			return Err(RunnerError::new(format!(
				"parent rootfs dir does not exist: {}",
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

fn copy_tree(source: &Path, dest: &Path) -> Result<(), BuildError> {
	for entry in fs::read_dir(source)? {
		let entry = entry?;
		let source_path = entry.path();
		let dest_path = dest.join(entry.file_name());
		let file_type = entry.file_type()?;
		if file_type.is_dir() {
			fs::create_dir_all(&dest_path)?;
			copy_tree(&source_path, &dest_path)?;
		} else if file_type.is_symlink() {
			let target = fs::read_link(&source_path)?;
			symlink(target, dest_path)?;
		} else if file_type.is_file() {
			if let Some(parent) = dest_path.parent() {
				fs::create_dir_all(parent)?;
			}
			fs::copy(&source_path, &dest_path)?;
			let permissions = fs::metadata(&source_path)?.permissions();
			fs::set_permissions(&dest_path, permissions)?;
		}
	}
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
