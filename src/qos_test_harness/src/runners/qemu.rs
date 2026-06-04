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
	BuildOutput, BuildProfile, BuildRecord, BuilderKind, EnclaveBinary,
	HostBinary, HostRunnerKind, HttpResponse, RunnerError, RunnerKind,
	RunningApp, StartAppSpec, TestOutcome, TestRunner, http_get, http_post,
	read_build_record, run_command, sha256_file_hex, sha256_hex,
	workspace_state, write_build_record,
};

const SIGNED_ECHO_BIN: &str = "signed_echo";
const QOS_CORE_BIN: &str = "qos_core";
const INIT_BIN: &str = "init";
const LIGHT_INIT_BIN: &str = "light_init";
const QOS_HOST_BIN: &str = "qos_host";
const QOS_CLIENT_BIN: &str = "qos_client";
const QOS_BRIDGE_BIN: &str = "qos_bridge";
const DEFAULT_APP_PORT: u16 = 3000;
const DEFAULT_LIGHT_GUEST_CONTROL_PORT: u16 = 3001;
const DEFAULT_INITRD_KERNEL_CMDLINE: &str =
	"console=ttyS0 panic=1 reboot=k root=/dev/ram0";
const DEFAULT_9P_KERNEL_CMDLINE: &str = "console=ttyS0 panic=1 reboot=k root=qosroot rootfstype=9p rootflags=trans=virtio,version=9p2000.L rw init=/init";
const DEFAULT_LIGHT_NET_DEVICE: &str = "e1000,netdev=qosnet";
const DEFAULT_PLAIN_NET_DEVICE: &str = "virtio-net-pci,netdev=qosnet";
const PLAIN_QEMU_CONTAINERFILE: &str =
	"src/qos_test_harness/docker/qemu_plain.Containerfile";
const DEFAULT_REPRODUCIBLE_KERNEL_IMAGE: &str = "linuxkit/kernel:6.6.71@sha256:3eae204fb152652742f4679da795a3f2848ad70c83bf1db31af0a0039e40ae67";
const DEFAULT_REPRODUCIBLE_KERNEL_PLATFORM: &str = "linux/amd64";
const DEFAULT_REPRODUCIBLE_KERNEL_PATH: &str = "/kernel";
const ROOTFS_DIR_METADATA: &str = "rootfs_dir";
const KERNEL_PATH_METADATA: &str = "kernel_path";
const KERNEL_SHA256_METADATA: &str = "kernel_sha256";
const KERNEL_IMAGE_METADATA: &str = "kernel_image";
const ROOTFS_LAYOUT_VERSION: u32 = 2;
const HOST_READY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuFlavor {
	Light,
	Reproducible,
}

impl QemuFlavor {
	#[must_use]
	pub fn runner_kind(self) -> RunnerKind {
		match self {
			Self::Light => RunnerKind::LightQemu,
			Self::Reproducible => RunnerKind::ReproducibleQemu,
		}
	}

	#[must_use]
	pub fn builder_kind(self) -> BuilderKind {
		match self {
			Self::Light => BuilderKind::LocalCrossCompile,
			Self::Reproducible => BuilderKind::StageX,
		}
	}

	fn dir_name(self) -> &'static str {
		match self {
			Self::Light => "light",
			Self::Reproducible => "reproducible",
		}
	}
}

#[derive(Debug, Clone)]
pub struct QemuRunnerConfig {
	pub workspace_root: PathBuf,
	pub output_dir: PathBuf,
	pub qemu_bin: PathBuf,
	pub light_kernel_path: Option<PathBuf>,
	pub light_kernel_cmdline: String,
	pub light_machine: Option<String>,
	pub light_cpu: Option<String>,
	pub light_net_device: String,
	pub light_use_9p_rootfs: bool,
	pub host: String,
	pub app_host_port: u16,
	pub control_port: u16,
	pub light_core_host_port: u16,
	pub light_guest_control_port: u16,
	pub app_port: u16,
	pub profile: BuildProfile,
	pub target_triple: String,
	pub target_linker: Option<String>,
	pub memory: String,
	pub enable_kvm: bool,
	pub keep_on_failure: bool,
	pub host_runner: HostRunnerKind,
}

impl QemuRunnerConfig {
	#[must_use]
	pub fn new(workspace_root: impl Into<PathBuf>, app_host_port: u16) -> Self {
		let workspace_root = workspace_root.into();
		let output_dir = workspace_root.join("target/qos-test-harness/qemu");
		let control_port = app_host_port
			.checked_add(1)
			.unwrap_or_else(|| app_host_port.saturating_sub(1));
		let light_core_host_port = app_host_port
			.checked_add(2)
			.unwrap_or_else(|| app_host_port.saturating_sub(2));

		Self {
			output_dir,
			workspace_root,
			qemu_bin: PathBuf::from("qemu-system-x86_64"),
			light_kernel_path: None,
			light_kernel_cmdline: DEFAULT_INITRD_KERNEL_CMDLINE.to_string(),
			light_machine: None,
			light_cpu: None,
			light_net_device: DEFAULT_LIGHT_NET_DEVICE.to_string(),
			light_use_9p_rootfs: false,
			host: "127.0.0.1".to_string(),
			app_host_port,
			control_port,
			light_core_host_port,
			light_guest_control_port: DEFAULT_LIGHT_GUEST_CONTROL_PORT,
			app_port: DEFAULT_APP_PORT,
			profile: BuildProfile::Release,
			target_triple: "x86_64-unknown-linux-musl".to_string(),
			target_linker: Some("x86_64-linux-musl-gcc".to_string()),
			memory: "4G".to_string(),
			enable_kvm: true,
			keep_on_failure: false,
			host_runner: HostRunnerKind::Native,
		}
	}
}

#[derive(Debug)]
pub struct CargoSignedEchoBuilder {
	config: QemuRunnerConfig,
	flavor: QemuFlavor,
}

struct PlainQemuPackage {
	pivot: BuildArtifact,
	enclave_binaries: Vec<EnclaveBinary>,
	rootfs: BuildArtifact,
}

impl CargoSignedEchoBuilder {
	#[must_use]
	pub fn new(config: QemuRunnerConfig, flavor: QemuFlavor) -> Self {
		Self { config, flavor }
	}

	fn flavor_dir(&self) -> PathBuf {
		self.config.output_dir.join(self.flavor.dir_name())
	}

	fn record_path(&self, key: &BuildKey) -> PathBuf {
		self.flavor_dir().join(format!("{}.json", key.0))
	}

	fn enclave_target_dir(&self) -> PathBuf {
		self.flavor_dir().join("enclave-target")
	}

	fn host_target_dir(&self) -> PathBuf {
		self.flavor_dir().join("host-target")
	}

	fn rootfs_dir(&self) -> PathBuf {
		match self.flavor {
			QemuFlavor::Light => self.flavor_dir().join("light-rootfs-dir"),
			QemuFlavor::Reproducible => {
				self.flavor_dir().join("plain-rootfs-dir")
			}
		}
	}

	fn rootfs_path(&self) -> PathBuf {
		match self.flavor {
			QemuFlavor::Light => self.flavor_dir().join("light-rootfs.cpio"),
			QemuFlavor::Reproducible => {
				self.flavor_dir().join("plain-rootfs.cpio")
			}
		}
	}

	fn reproducible_package_dir(&self) -> PathBuf {
		self.flavor_dir().join("plain-package")
	}

	fn reproducible_kernel_path(&self) -> PathBuf {
		self.flavor_dir().join("linuxkit-kernel")
	}

	fn pivot_path(&self) -> PathBuf {
		self.enclave_target_dir()
			.join(&self.config.target_triple)
			.join(self.config.profile.target_dir_segment())
			.join(SIGNED_ECHO_BIN)
	}

	fn host_binary_path(&self, bin: &str) -> PathBuf {
		self.host_target_dir()
			.join(self.config.profile.target_dir_segment())
			.join(bin)
	}

	fn enclave_binary_path(&self, bin: &str) -> PathBuf {
		self.enclave_target_dir()
			.join(&self.config.target_triple)
			.join(self.config.profile.target_dir_segment())
			.join(bin)
	}

	fn build_pivot(&self) -> Result<BuildArtifact, BuildError> {
		let target_dir = self.enclave_target_dir();
		let mut command = Command::new("cargo");
		command
			.arg("build")
			.arg("--locked")
			.arg("-p")
			.arg("qos_test_harness")
			.arg("--bin")
			.arg(SIGNED_ECHO_BIN)
			.arg("--target")
			.arg(&self.config.target_triple)
			.arg("--target-dir")
			.arg(&target_dir)
			.current_dir(&self.config.workspace_root);
		self.configure_target_linker(&mut command);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			command.arg(profile);
		}
		run_command(&mut command)?;

		let path = self.pivot_path();
		if !path.exists() {
			return Err(BuildError::MissingArtifact(
				path.display().to_string(),
			));
		}
		Ok(BuildArtifact { sha256_hex: sha256_file_hex(&path)?, path })
	}

	fn build_host_binaries(&self) -> Result<Vec<HostBinary>, BuildError> {
		let mut binaries = Vec::new();
		for bin in [QOS_HOST_BIN, QOS_CLIENT_BIN, QOS_BRIDGE_BIN] {
			let mut command = Command::new("cargo");
			command
				.arg("build")
				.arg("--locked")
				.arg("-p")
				.arg(bin)
				.arg("--bin")
				.arg(bin)
				.arg("--target-dir")
				.arg(self.host_target_dir())
				.current_dir(&self.config.workspace_root);
			if let Some(profile) = self.config.profile.as_cargo_arg() {
				command.arg(profile);
			}
			run_command(&mut command)?;

			let path = self.host_binary_path(bin);
			if !path.exists() {
				return Err(BuildError::MissingArtifact(
					path.display().to_string(),
				));
			}
			binaries.push(HostBinary {
				name: bin.to_string(),
				artifact: BuildArtifact {
					sha256_hex: sha256_file_hex(&path)?,
					path,
				},
			});
		}
		Ok(binaries)
	}

	fn build_light_enclave_binaries(
		&self,
	) -> Result<Vec<EnclaveBinary>, BuildError> {
		if self.flavor != QemuFlavor::Light {
			return Ok(Vec::new());
		}

		let mut core = Command::new("cargo");
		core.arg("build")
			.arg("--locked")
			.arg("-p")
			.arg(QOS_CORE_BIN)
			.arg("--bin")
			.arg(QOS_CORE_BIN)
			.arg("--features")
			.arg("mock")
			.arg("--target")
			.arg(&self.config.target_triple)
			.arg("--target-dir")
			.arg(self.enclave_target_dir())
			.current_dir(&self.config.workspace_root);
		self.configure_target_linker(&mut core);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			core.arg(profile);
		}
		run_command(&mut core)?;

		let mut light_init = Command::new("cargo");
		light_init
			.arg("build")
			.arg("--locked")
			.arg("-p")
			.arg("qos_test_harness")
			.arg("--bin")
			.arg(LIGHT_INIT_BIN)
			.arg("--target")
			.arg(&self.config.target_triple)
			.arg("--target-dir")
			.arg(self.enclave_target_dir())
			.current_dir(&self.config.workspace_root);
		self.configure_target_linker(&mut light_init);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			light_init.arg(profile);
		}
		run_command(&mut light_init)?;

		let mut init = Command::new("cargo");
		init.arg("build")
			.arg("--locked")
			.arg("--manifest-path")
			.arg("src/init/Cargo.toml")
			.arg("--bin")
			.arg(INIT_BIN)
			.arg("--target")
			.arg(&self.config.target_triple)
			.arg("--target-dir")
			.arg(self.enclave_target_dir())
			.env("RUSTFLAGS", "-C target-feature=+crt-static")
			.current_dir(&self.config.workspace_root);
		self.configure_target_linker(&mut init);
		if let Some(profile) = self.config.profile.as_cargo_arg() {
			init.arg(profile);
		}
		run_command(&mut init)?;

		[QOS_CORE_BIN, LIGHT_INIT_BIN, INIT_BIN]
			.into_iter()
			.map(|name| {
				let path = self.enclave_binary_path(name);
				if !path.exists() {
					return Err(BuildError::MissingArtifact(
						path.display().to_string(),
					));
				}
				Ok(EnclaveBinary {
					name: name.to_string(),
					artifact: BuildArtifact {
						sha256_hex: sha256_file_hex(&path)?,
						path,
					},
				})
			})
			.collect()
	}

	fn package_light_initramfs(
		&self,
		enclave_binaries: &[EnclaveBinary],
	) -> Result<Option<BuildArtifact>, BuildError> {
		if self.flavor != QemuFlavor::Light {
			return Ok(None);
		}

		let qos_core = find_enclave_binary(enclave_binaries, QOS_CORE_BIN)?;
		let light_init = find_enclave_binary(enclave_binaries, LIGHT_INIT_BIN)?;
		let rootfs_path = self.rootfs_path();
		write_light_rootfs_dir(
			&self.rootfs_dir(),
			&light_init.artifact.path,
			&qos_core.artifact.path,
		)?;
		write_light_rootfs(
			&rootfs_path,
			&light_init.artifact.path,
			&qos_core.artifact.path,
		)?;
		Ok(Some(BuildArtifact {
			sha256_hex: sha256_file_hex(&rootfs_path)?,
			path: rootfs_path,
		}))
	}

	fn configure_target_linker(&self, command: &mut Command) {
		let Some(linker) = self.config.target_linker.as_ref() else {
			return;
		};
		let env_key = format!(
			"CARGO_TARGET_{}_LINKER",
			self.config.target_triple.replace('-', "_").to_ascii_uppercase()
		);
		command.env(env_key, linker);
	}

	fn build_reproducible_plain_package(
		&self,
		key: &BuildKey,
	) -> Result<PlainQemuPackage, BuildError> {
		if self.flavor != QemuFlavor::Reproducible {
			return Err(BuildError::InvalidOutput(
				"plain package builder is only valid for reproducible QEMU"
					.into(),
			));
		}

		let out_dir = self.flavor_dir();
		fs::create_dir_all(&out_dir)?;
		let tar_path = out_dir.join("plain-package.tar");
		let package_dir = self.reproducible_package_dir();
		if package_dir.exists() {
			fs::remove_dir_all(&package_dir)?;
		}
		fs::create_dir_all(&package_dir)?;
		let image_tag = format!("qos-qemu-plain:{}", key.0);

		run_command(
			Command::new("make")
				.arg("out/.common-loaded")
				.current_dir(&self.config.workspace_root),
		)?;

		run_command(
			Command::new("docker")
				.arg("build")
				.arg("--platform")
				.arg(DEFAULT_REPRODUCIBLE_KERNEL_PLATFORM)
				.arg("-t")
				.arg(image_tag)
				.arg("-f")
				.arg(PLAIN_QEMU_CONTAINERFILE)
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

		let pivot = artifact_for_path(&package_dir.join(SIGNED_ECHO_BIN))?;
		let qos_core = artifact_for_path(&package_dir.join(QOS_CORE_BIN))?;
		let init = artifact_for_path(&package_dir.join(INIT_BIN))?;
		let rootfs_path = self.rootfs_path();
		write_light_rootfs_dir(&self.rootfs_dir(), &init.path, &qos_core.path)?;
		write_light_rootfs(&rootfs_path, &init.path, &qos_core.path)?;

		Ok(PlainQemuPackage {
			pivot,
			enclave_binaries: vec![
				EnclaveBinary {
					name: QOS_CORE_BIN.to_string(),
					artifact: qos_core,
				},
				EnclaveBinary {
					name: LIGHT_INIT_BIN.to_string(),
					artifact: init,
				},
			],
			rootfs: artifact_for_path(&rootfs_path)?,
		})
	}

	fn plain_kernel_artifact(
		&self,
	) -> Result<Option<BuildArtifact>, BuildError> {
		if let Some(path) = self.config.light_kernel_path.as_ref() {
			return Ok(Some(artifact_for_path(path)?));
		}
		if self.flavor != QemuFlavor::Reproducible {
			return Ok(None);
		}

		let kernel_path = self.reproducible_kernel_path();
		if !kernel_path.exists() {
			if let Some(parent) = kernel_path.parent() {
				fs::create_dir_all(parent)?;
			}
			let container_id = run_command(
				Command::new("docker")
					.arg("create")
					.arg("--platform")
					.arg(DEFAULT_REPRODUCIBLE_KERNEL_PLATFORM)
					.arg(DEFAULT_REPRODUCIBLE_KERNEL_IMAGE)
					.arg("/bin/true"),
			)?;
			let container_id = container_id.trim();
			let copy_result = run_command(
				Command::new("docker")
					.arg("cp")
					.arg(format!(
						"{container_id}:{DEFAULT_REPRODUCIBLE_KERNEL_PATH}"
					))
					.arg(&kernel_path),
			);
			let _ =
				run_command(Command::new("docker").arg("rm").arg(container_id));
			copy_result?;
		}

		Ok(Some(artifact_for_path(&kernel_path)?))
	}
}

impl ArtifactBuilder for CargoSignedEchoBuilder {
	fn build_key(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildKey, BuildError> {
		let workspace = workspace_state(&plan.workspace_root);
		let raw = serde_json::json!({
			"workspace": workspace,
			"builder": plan.builder,
			"runner": plan.request.runner,
			"host_runner": plan.request.host_runner,
			"profile": plan.profile,
			"target": plan.target_triple,
			"target_linker": self.config.target_linker,
			"package": plan.package,
			"bin": plan.bin,
			"qemu_flavor": format!("{:?}", self.flavor),
			"rootfs_layout_version": ROOTFS_LAYOUT_VERSION,
			"plain_qemu_containerfile": PLAIN_QEMU_CONTAINERFILE,
			"reproducible_kernel_image": DEFAULT_REPRODUCIBLE_KERNEL_IMAGE,
			"light_kernel_path": self.config.light_kernel_path,
			"light_kernel_cmdline": self.config.light_kernel_cmdline,
			"light_machine": self.config.light_machine,
			"light_cpu": self.config.light_cpu,
			"light_net_device": self.config.light_net_device,
			"light_use_9p_rootfs": self.config.light_use_9p_rootfs,
			"light_guest_control_port": self.config.light_guest_control_port,
			"app_port": self.config.app_port,
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

		let host_binaries = self.build_host_binaries()?;
		let (pivot, enclave_binaries, rootfs) = match self.flavor {
			QemuFlavor::Light => {
				let pivot = self.build_pivot()?;
				let enclave_binaries = self.build_light_enclave_binaries()?;
				let rootfs = self.package_light_initramfs(&enclave_binaries)?;
				(pivot, enclave_binaries, rootfs)
			}
			QemuFlavor::Reproducible => {
				let package = self.build_reproducible_plain_package(&key)?;
				(package.pivot, package.enclave_binaries, Some(package.rootfs))
			}
		};
		let eif = None;
		let kernel = self.plain_kernel_artifact()?;
		let mut metadata = BTreeMap::new();
		if rootfs.is_some() {
			metadata.insert(
				ROOTFS_DIR_METADATA.to_string(),
				self.rootfs_dir().display().to_string(),
			);
		}
		if let Some(kernel) = kernel.as_ref() {
			metadata.insert(
				KERNEL_PATH_METADATA.to_string(),
				kernel.path.display().to_string(),
			);
			metadata.insert(
				KERNEL_SHA256_METADATA.to_string(),
				kernel.sha256_hex.clone(),
			);
			if self.flavor == QemuFlavor::Reproducible
				&& self.config.light_kernel_path.is_none()
			{
				metadata.insert(
					KERNEL_IMAGE_METADATA.to_string(),
					DEFAULT_REPRODUCIBLE_KERNEL_IMAGE.to_string(),
				);
			}
		}
		let output = BuildOutput {
			key: key.clone(),
			builder: self.flavor.builder_kind(),
			runner: self.flavor.runner_kind(),
			host_runner: self.config.host_runner.clone(),
			workspace: workspace_state(&plan.workspace_root),
			pivot: Some(pivot),
			host_binaries,
			enclave_binaries,
			image_ref: None,
			image_id: None,
			eif,
			rootfs,
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
		for host_binary in &output.host_binaries {
			validate_artifact(&host_binary.artifact)?;
		}
		for enclave_binary in &output.enclave_binaries {
			validate_artifact(&enclave_binary.artifact)?;
		}
		if let Some(eif) = output.eif.as_ref() {
			validate_artifact(eif)?;
		}
		if let Some(rootfs) = output.rootfs.as_ref() {
			validate_artifact(rootfs)?;
		}
		if let Some(rootfs_dir) = output
			.metadata
			.get(ROOTFS_DIR_METADATA)
			.or_else(|| output.metadata.get("light_rootfs_dir"))
			&& !Path::new(rootfs_dir).is_dir()
		{
			return Err(BuildError::MissingArtifact(rootfs_dir.clone()));
		}
		if let Some(kernel_path) = output.metadata.get(KERNEL_PATH_METADATA) {
			let kernel = BuildArtifact {
				path: PathBuf::from(kernel_path),
				sha256_hex: output
					.metadata
					.get(KERNEL_SHA256_METADATA)
					.cloned()
					.ok_or_else(|| {
						BuildError::MissingArtifact(
							KERNEL_SHA256_METADATA.to_string(),
						)
					})?,
			};
			validate_artifact(&kernel)?;
		}
		Ok(())
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

fn find_enclave_binary<'a>(
	binaries: &'a [EnclaveBinary],
	name: &str,
) -> Result<&'a EnclaveBinary, BuildError> {
	binaries.iter().find(|binary| binary.name == name).ok_or_else(|| {
		BuildError::MissingArtifact(format!("enclave binary `{name}`"))
	})
}

fn write_light_rootfs(
	path: &Path,
	light_init: &Path,
	qos_core: &Path,
) -> Result<(), BuildError> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let mut out = File::create(path)?;
	let mut ino = 1;
	write_newc_dir(&mut out, &mut ino, "dev")?;
	write_newc_dir(&mut out, &mut ino, "proc")?;
	write_newc_dir(&mut out, &mut ino, "sys")?;
	write_newc_dir(&mut out, &mut ino, "tmp")?;
	write_newc_char(&mut out, &mut ino, "dev/console", 5, 1)?;
	write_newc_char(&mut out, &mut ino, "dev/null", 1, 3)?;
	write_newc_file(&mut out, &mut ino, "init", light_init)?;
	write_newc_file(&mut out, &mut ino, "qos_core", qos_core)?;
	write_newc_trailer(&mut out, &mut ino)?;
	Ok(())
}

fn write_light_rootfs_dir(
	root: &Path,
	light_init: &Path,
	qos_core: &Path,
) -> Result<(), BuildError> {
	if root.exists() {
		fs::remove_dir_all(root)?;
	}
	fs::create_dir_all(root)?;
	for dir in ["dev", "proc", "sys", "tmp"] {
		fs::create_dir_all(root.join(dir))?;
	}
	fs::set_permissions(root.join("tmp"), fs::Permissions::from_mode(0o1777))?;
	File::create(root.join("dev/null"))?;
	fs::set_permissions(
		root.join("dev/null"),
		fs::Permissions::from_mode(0o666),
	)?;
	copy_executable(light_init, &root.join("init"))?;
	copy_executable(qos_core, &root.join("qos_core"))?;
	Ok(())
}

fn copy_executable(source: &Path, dest: &Path) -> Result<(), BuildError> {
	fs::copy(source, dest)?;
	fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
	Ok(())
}

fn write_newc_dir(
	out: &mut File,
	ino: &mut u32,
	name: &str,
) -> Result<(), BuildError> {
	write_newc_entry(
		out,
		NewcHeader {
			ino: *ino,
			mode: 0o040755,
			nlink: 2,
			rdev_major: 0,
			rdev_minor: 0,
		},
		name,
		&[],
	)?;
	*ino += 1;
	Ok(())
}

fn write_newc_char(
	out: &mut File,
	ino: &mut u32,
	name: &str,
	major: u32,
	minor: u32,
) -> Result<(), BuildError> {
	write_newc_entry(
		out,
		NewcHeader {
			ino: *ino,
			mode: 0o020600,
			nlink: 1,
			rdev_major: major,
			rdev_minor: minor,
		},
		name,
		&[],
	)?;
	*ino += 1;
	Ok(())
}

fn write_newc_file(
	out: &mut File,
	ino: &mut u32,
	name: &str,
	path: &Path,
) -> Result<(), BuildError> {
	let bytes = fs::read(path)?;
	write_newc_entry(
		out,
		NewcHeader {
			ino: *ino,
			mode: 0o100755,
			nlink: 1,
			rdev_major: 0,
			rdev_minor: 0,
		},
		name,
		&bytes,
	)?;
	*ino += 1;
	Ok(())
}

fn write_newc_trailer(out: &mut File, ino: &mut u32) -> Result<(), BuildError> {
	write_newc_entry(
		out,
		NewcHeader {
			ino: *ino,
			mode: 0,
			nlink: 1,
			rdev_major: 0,
			rdev_minor: 0,
		},
		"TRAILER!!!",
		&[],
	)?;
	*ino += 1;
	Ok(())
}

struct NewcHeader {
	ino: u32,
	mode: u32,
	nlink: u32,
	rdev_major: u32,
	rdev_minor: u32,
}

fn write_newc_entry(
	out: &mut File,
	header: NewcHeader,
	name: &str,
	data: &[u8],
) -> Result<(), BuildError> {
	let name_size = name.len() + 1;
	write!(
		out,
		"070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{file_size:08x}{dev_major:08x}{dev_minor:08x}{rdev_major:08x}{rdev_minor:08x}{name_size:08x}{check:08x}",
		ino = header.ino,
		mode = header.mode,
		uid = 0,
		gid = 0,
		nlink = header.nlink,
		mtime = 0,
		file_size = data.len(),
		dev_major = 0,
		dev_minor = 0,
		rdev_major = header.rdev_major,
		rdev_minor = header.rdev_minor,
		check = 0,
	)?;
	out.write_all(name.as_bytes())?;
	out.write_all(&[0])?;
	pad_newc(out, 110 + name_size)?;
	out.write_all(data)?;
	pad_newc(out, data.len())?;
	Ok(())
}

fn pad_newc(out: &mut File, len: usize) -> Result<(), BuildError> {
	let pad = (4 - (len % 4)) % 4;
	if pad > 0 {
		out.write_all(&vec![0; pad])?;
	}
	Ok(())
}

#[derive(Debug)]
pub struct QemuTestRunner {
	config: QemuRunnerConfig,
	flavor: QemuFlavor,
	builder: CargoSignedEchoBuilder,
	build_output: Option<BuildOutput>,
	children: Vec<ManagedChild>,
}

impl QemuTestRunner {
	#[must_use]
	pub fn light(config: QemuRunnerConfig) -> Self {
		Self::new(config, QemuFlavor::Light)
	}

	#[must_use]
	pub fn reproducible(mut config: QemuRunnerConfig) -> Self {
		if config.light_kernel_cmdline == DEFAULT_INITRD_KERNEL_CMDLINE {
			config.light_kernel_cmdline = DEFAULT_9P_KERNEL_CMDLINE.to_string();
		}
		if config.light_net_device == DEFAULT_LIGHT_NET_DEVICE {
			config.light_net_device = DEFAULT_PLAIN_NET_DEVICE.to_string();
		}
		config.light_use_9p_rootfs = true;
		Self::new(config, QemuFlavor::Reproducible)
	}

	fn new(config: QemuRunnerConfig, flavor: QemuFlavor) -> Self {
		let builder = CargoSignedEchoBuilder::new(config.clone(), flavor);
		Self { config, flavor, builder, build_output: None, children: vec![] }
	}

	pub fn preflight(&self) -> Result<(), RunnerError> {
		command_exists(&self.config.qemu_bin)?;
		if self.config.host_runner == HostRunnerKind::Native
			&& !cfg!(target_os = "linux")
			&& !self.uses_plain_qemu()
		{
			return Err(RunnerError::new(
				"native-host QEMU runner requires a plain kernel boot on non-Linux hosts",
			));
		}
		if self.config.host_runner != HostRunnerKind::Native {
			return Err(RunnerError::new(format!(
				"host runner {:?} is planned but not implemented yet",
				self.config.host_runner
			)));
		}
		if self.flavor == QemuFlavor::Light
			&& let Some(linker) = self.config.target_linker.as_ref()
		{
			command_exists(Path::new(linker))?;
		}
		if let Some(kernel) = self.config.light_kernel_path.as_ref()
			&& !kernel.exists()
		{
			return Err(RunnerError::new(format!(
				"QEMU kernel path does not exist: {}",
				kernel.display()
			)));
		}
		if !self.uses_plain_qemu() {
			return Err(RunnerError::new(
				"QEMU runner uses plain kernel emulation; configure a kernel path",
			));
		}
		if self.flavor == QemuFlavor::Reproducible {
			run_command(Command::new("docker").arg("info"))
				.map(|_| ())
				.map_err(RunnerError::from)?;
		}
		Ok(())
	}

	fn build_plan(&self, request: ArtifactRequest) -> ArtifactBuildPlan {
		ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: request,
				runner: self.flavor.runner_kind(),
				host_runner: self.config.host_runner.clone(),
			},
			workspace_root: self.config.workspace_root.clone(),
			output_dir: self.config.output_dir.clone(),
			builder: self.flavor.builder_kind(),
			profile: self.config.profile.clone(),
			target_triple: Some(self.config.target_triple.clone()),
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

	fn uses_plain_qemu(&self) -> bool {
		self.flavor == QemuFlavor::Reproducible
			|| (self.flavor == QemuFlavor::Light
				&& self.config.light_kernel_path.is_some())
	}

	fn start_app_inner(
		&mut self,
		spec: StartAppSpec,
	) -> Result<RunningApp, RunnerError> {
		let (path, sha256_hex) = match &spec.artifact {
			AppArtifact::LocalBinary { path, sha256_hex } => {
				(path.clone(), sha256_hex.clone())
			}
			AppArtifact::OciImage { .. } => {
				return Err(RunnerError::new(
					"qemu runner requires a local pivot binary",
				));
			}
		};
		if let Some(expected) = sha256_hex {
			let actual = sha256_file_hex(&path).map_err(RunnerError::from)?;
			if actual != expected {
				return Err(RunnerError::new(format!(
					"pivot hash mismatch for {}: expected {expected}, actual {actual}",
					path.display()
				)));
			}
		}

		let run_id = timestamp_millis();
		let run_dir = self
			.config
			.output_dir
			.join(self.flavor.dir_name())
			.join("run")
			.join(run_id.to_string());
		fs::create_dir_all(&run_dir).map_err(io_error)?;

		let mut metadata = BTreeMap::new();
		let rootfs = self.rootfs_for_start()?;
		self.start_plain_qemu(&run_dir, &rootfs.path)?;
		metadata.insert("rootfs_sha256".to_string(), rootfs.sha256_hex);
		self.start_qos_host(&run_dir)?;
		self.wait_host_ready()?;
		self.run_dangerous_dev_boot(&path, &spec)?;

		metadata.insert("run_dir".to_string(), run_dir.display().to_string());
		metadata
			.insert("qemu_flavor".to_string(), format!("{:?}", self.flavor));
		metadata.insert(
			"host_runner".to_string(),
			format!("{:?}", self.config.host_runner),
		);
		metadata.insert(
			"pivot_sha256".to_string(),
			sha256_file_hex(&path).map_err(RunnerError::from)?,
		);

		Ok(RunningApp { id: run_id.to_string(), metadata })
	}

	fn rootfs_for_start(&self) -> Result<BuildArtifact, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		output.rootfs.clone().ok_or_else(|| {
			RunnerError::new("plain QEMU builder returned no rootfs")
		})
	}

	fn rootfs_dir_for_start(&self) -> Result<PathBuf, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path = output
			.metadata
			.get(ROOTFS_DIR_METADATA)
			.or_else(|| output.metadata.get("light_rootfs_dir"))
			.ok_or_else(|| {
				RunnerError::new("plain QEMU builder returned no rootfs dir")
			})?;
		let path = PathBuf::from(path);
		if !path.is_dir() {
			return Err(RunnerError::new(format!(
				"plain QEMU rootfs dir does not exist: {}",
				path.display()
			)));
		}
		Ok(path)
	}

	fn kernel_for_start(&self) -> Result<PathBuf, RunnerError> {
		if let Some(kernel) = self.config.light_kernel_path.as_ref() {
			return Ok(kernel.clone());
		}
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		let path =
			output.metadata.get(KERNEL_PATH_METADATA).ok_or_else(|| {
				RunnerError::new("plain QEMU builder returned no kernel")
			})?;
		let path = PathBuf::from(path);
		if !path.exists() {
			return Err(RunnerError::new(format!(
				"plain QEMU kernel does not exist: {}",
				path.display()
			)));
		}
		Ok(path)
	}

	fn host_binary(&self, name: &str) -> Result<PathBuf, RunnerError> {
		let output = self.build_output.as_ref().ok_or_else(|| {
			RunnerError::new("prepare_artifact must run before start_app")
		})?;
		output
			.host_binaries
			.iter()
			.find(|bin| bin.name == name)
			.map(|bin| bin.artifact.path.clone())
			.ok_or_else(|| {
				RunnerError::new(format!("missing host binary `{name}`"))
			})
	}

	fn start_plain_qemu(
		&mut self,
		run_dir: &Path,
		rootfs_path: &Path,
	) -> Result<(), RunnerError> {
		let kernel = self.kernel_for_start()?;
		let mut command = Command::new(&self.config.qemu_bin);
		let kernel_cmdline = format!(
			"{} ip=dhcp -- qos_tcp_host=0.0.0.0 qos_tcp_port={}",
			self.config.light_kernel_cmdline,
			self.config.light_guest_control_port
		);
		if let Some(machine) = self.config.light_machine.as_ref() {
			command.arg("-machine").arg(machine);
		}
		command
			.arg("-kernel")
			.arg(&kernel)
			.arg("-append")
			.arg(kernel_cmdline)
			.arg("-nographic")
			.arg("-m")
			.arg(&self.config.memory)
			.arg("-netdev")
			.arg(format!(
				"user,id=qosnet,hostfwd=tcp:{}:{}-:{},hostfwd=tcp:{}:{}-:{}",
				self.config.host,
				self.config.light_core_host_port,
				self.config.light_guest_control_port,
				self.config.host,
				self.config.app_host_port,
				self.config.app_port
			))
			.arg("-device")
			.arg(&self.config.light_net_device);
		if self.config.light_use_9p_rootfs {
			let rootfs_dir = self.rootfs_dir_for_start()?;
			command.arg("-virtfs").arg(format!(
				"local,path={},mount_tag=qosroot,security_model=none",
				rootfs_dir.display()
			));
		} else {
			command.arg("-initrd").arg(rootfs_path);
		}
		if self.config.enable_kvm {
			command.arg("--enable-kvm");
			if self.config.light_cpu.is_none() {
				command.arg("-cpu").arg("host");
			}
		}
		if let Some(cpu) = self.config.light_cpu.as_ref() {
			command.arg("-cpu").arg(cpu);
		}
		let child = spawn_logged("qemu-plain", &mut command, run_dir)?;
		self.children.push(child);
		Ok(())
	}

	fn start_qos_host(&mut self, run_dir: &Path) -> Result<(), RunnerError> {
		let mut command = Command::new(self.host_binary(QOS_HOST_BIN)?);
		command.args([
			"--host-ip",
			&self.config.host,
			"--host-port",
			&self.config.control_port.to_string(),
		]);
		command.args([
			"--tcp-host",
			&self.config.host,
			"--tcp-port",
			&self.config.light_core_host_port.to_string(),
		]);
		let child = spawn_logged(QOS_HOST_BIN, &mut command, run_dir)?;
		self.children.push(child);
		Ok(())
	}

	fn wait_host_ready(&mut self) -> Result<(), RunnerError> {
		let url = format!(
			"http://{}:{}/qos/host-health",
			self.config.host, self.config.control_port
		);
		wait_for_http_ok(&url, HOST_READY_TIMEOUT, &mut self.children)
	}

	fn run_dangerous_dev_boot(
		&self,
		pivot_path: &Path,
		spec: &StartAppSpec,
	) -> Result<(), RunnerError> {
		let bridge_config = format!(
			"[{{\"type\":\"server\",\"port\":{},\"host\":\"{}\"}}]",
			self.config.app_port, self.config.host
		);
		let pivot_args = encode_pivot_args(&spec.pivot_args)?;
		let mut command = Command::new(self.host_binary(QOS_CLIENT_BIN)?);
		command
			.arg("dangerous-dev-boot")
			.arg("--host-ip")
			.arg(&self.config.host)
			.arg("--host-port")
			.arg(self.config.control_port.to_string())
			.arg("--pivot-path")
			.arg(pivot_path)
			.arg("--restart-policy")
			.arg("never")
			.arg("--pivot-args")
			.arg(pivot_args);
		if !self.uses_plain_qemu() {
			command.arg("--bridge-config").arg(bridge_config);
		}
		if self.uses_plain_qemu() && self.config.light_use_9p_rootfs {
			command.arg("--unsafe-eph-path-override").arg(
				self.rootfs_dir_for_start()?.join("tmp/qos.ephemeral.key"),
			);
		}
		run_command(&mut command).map(|_| ()).map_err(RunnerError::from)
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

impl TestRunner for QemuTestRunner {
	async fn prepare_artifact(
		&mut self,
		request: ArtifactRequest,
	) -> Result<AppArtifact, RunnerError> {
		self.preflight()?;
		let output = self.builder.build(&self.build_plan(request)).await?;
		let pivot = output.pivot.clone().ok_or_else(|| {
			RunnerError::new("qemu builder returned no pivot")
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

fn timestamp_millis() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system clock before unix epoch")
		.as_millis()
}

fn io_error(err: std::io::Error) -> RunnerError {
	RunnerError::new(err.to_string())
}
