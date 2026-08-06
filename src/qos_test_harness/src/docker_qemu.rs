//! Docker-host/QEMU-Nitro runner implementation.

use std::{
	ffi::OsString,
	path::{Path, PathBuf},
	process::{Child, Command, Stdio},
	time::Duration,
};

use qos_core::protocol::services::boot::RestartPolicy;

use crate::{
	ApprovingUserMaterial, BootClientFixture, BridgeConfig, DockerProgram,
	DockerRunSpec, DockerVolumeSocket, Eif, ImageRef, MaterialFile, Pivot,
	RunnerError, RunningApp, RunningAppGuard, StartAppSpec, TestRunner,
	VersionedManifest,
};

/// Runner spec for Docker host + QEMU Nitro guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerHostQemuNitroSpec {
	/// EIF to boot in QEMU.
	pub eif: Eif,
	/// `qos_host` program.
	pub host_program: DockerProgram,
	/// Docker access policy for `qos_host`.
	pub host_run: DockerRunSpec,
	/// `qos_bridge` ingress program.
	pub bridge_program: DockerProgram,
	/// Docker access policy for `qos_bridge`.
	pub bridge_run: DockerRunSpec,
	/// Optional egress binary path visible inside the bridge container.
	pub bridge_egress_bin_path: Option<PathBuf>,
	/// `qos_client` program.
	pub client_program: DockerProgram,
	/// Docker access policy for `qos_client`.
	pub client_run: DockerRunSpec,
	/// QEMU runtime configuration.
	pub qemu: QemuRuntimeSpec,
	/// Fixture material used to approve and boot a test manifest.
	pub boot_fixture: BootClientFixture,
}

/// QEMU runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuRuntimeSpec {
	/// QEMU binary path.
	pub qemu_bin: PathBuf,
	/// `vhost-device-vsock` binary path.
	pub vhost_device_vsock_bin: PathBuf,
	/// Optional Docker image used to run QEMU and `vhost-device-vsock`.
	pub qemu_tool_image: Option<ImageRef>,
	/// Optional Docker image used to configure host-side egress networking.
	pub egress_setup_image: Option<ImageRef>,
	/// Docker volume socket used by QEMU tool containers.
	pub qemu_tool_vhost_socket: Option<DockerVolumeSocket>,
	/// Docker binary path.
	pub docker_bin: PathBuf,
	/// Docker access policy for QEMU and vhost tool containers.
	pub docker_tool_run: DockerRunSpec,
	/// Whether runner containers should use Docker host networking.
	pub docker_host_network: bool,
	/// Work directory.
	pub work_dir: PathBuf,
	/// Vhost socket path.
	pub vhost_socket_path: PathBuf,
	/// Guest CID.
	pub guest_cid: u32,
	/// Host CID.
	pub host_cid: u32,
	/// Control VSOCK port exposed by the guest.
	pub control_vsock_port: u16,
	/// Host IP for `qos_host` and client calls.
	pub host_ip: String,
	/// Hostname or IP clients use to reach `qos_host`.
	pub host_connect_ip: String,
	/// Hostname or IP returned to tests for ingress probes.
	pub ingress_ip: String,
	/// Host HTTP port for `qos_host`.
	pub host_port: u16,
	/// Host HTTP port exposed by `qos_bridge` for app ingress.
	pub ingress_port: u16,
	/// QEMU memory argument, for example `4G`.
	pub memory: String,
	/// QEMU CPU argument, for example `host`.
	pub cpu: String,
	/// Whether to pass `--enable-kvm`.
	pub enable_kvm: bool,
	/// Delay after starting long-running runtime processes.
	pub startup_delay: Duration,
	/// Delay before boot orchestration after QEMU starts.
	pub guest_boot_delay: Duration,
	/// Timeout for host and enclave readiness checks.
	pub readiness_timeout: Duration,
}

/// Scratch paths used while booting one app.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootWorkspace {
	/// Directory where material is staged for path-based CLI commands.
	input_dir: PathBuf,
	/// Staged PCR3 preimage path.
	pcr3_preimage_path: PathBuf,
	/// Staged QOS release directory.
	qos_release_dir: PathBuf,
	/// Staged manifest key set directory.
	manifest_set_dir: PathBuf,
	/// Staged share key set directory.
	share_set_dir: PathBuf,
	/// Staged quorum public key path.
	quorum_key_path: PathBuf,
	/// Staged user material directory.
	users_dir: PathBuf,
	/// Directory where manifest approvals are written.
	boot_dir: PathBuf,
	/// Directory where attestation artifacts are written.
	attestation_dir: PathBuf,
	/// Pivot hash path.
	pivot_hash_path: PathBuf,
	/// Manifest path.
	manifest_path: PathBuf,
	/// Manifest envelope path.
	manifest_envelope_path: PathBuf,
	/// Attestation doc path.
	attestation_doc_path: PathBuf,
}

impl BootWorkspace {
	/// Create scratch paths under `root`.
	#[must_use]
	pub fn under(root: impl AsRef<Path>) -> Self {
		let root = root.as_ref();
		let input_dir = root.join("input");
		let boot_dir = root.join("boot");
		let attestation_dir = root.join("attestation");
		Self {
			pcr3_preimage_path: input_dir.join("pcr3-preimage"),
			qos_release_dir: input_dir.join("qos-release"),
			manifest_set_dir: input_dir.join("manifest-set"),
			share_set_dir: input_dir.join("share-set"),
			quorum_key_path: input_dir.join("quorum_key.pub"),
			users_dir: input_dir.join("users"),
			input_dir,
			pivot_hash_path: boot_dir.join("pivot.sha256"),
			manifest_path: boot_dir.join("manifest"),
			manifest_envelope_path: boot_dir.join("manifest_envelope"),
			attestation_doc_path: attestation_dir.join("attestation_doc"),
			boot_dir,
			attestation_dir,
		}
	}

	/// Ephemeral wrapped share path for a user alias.
	#[must_use]
	pub fn eph_wrapped_share_path(&self, alias: &str) -> PathBuf {
		self.boot_dir.join(format!("{alias}.eph_wrapped.share"))
	}

	/// Attestation approval path for a user alias.
	#[must_use]
	pub fn attestation_approval_path(&self, alias: &str) -> PathBuf {
		self.boot_dir.join(format!("{alias}.attestation.approval"))
	}
	/// Staged user secret path.
	#[must_use]
	pub fn user_secret_path(&self, alias: &str) -> PathBuf {
		self.users_dir
			.join(sanitize_name(alias))
			.join(format!("{alias}.secret"))
	}
	/// Staged user share path.
	#[must_use]
	pub fn user_share_path(&self, alias: &str) -> PathBuf {
		self.users_dir.join(sanitize_name(alias)).join(format!("{alias}.share"))
	}
}

/// Docker host + QEMU Nitro guest runner.
#[derive(Debug)]
pub struct DockerHostQemuNitroRunner {
	spec: DockerHostQemuNitroSpec,
	children: Vec<ManagedChild>,
}

impl DockerHostQemuNitroRunner {
	/// Create a runner from its spec.
	#[must_use]
	pub fn new(spec: DockerHostQemuNitroSpec) -> Self {
		Self { spec, children: Vec::new() }
	}

	/// Build arguments for `vhost-device-vsock`.
	#[must_use]
	pub fn vhost_device_vsock_args(&self) -> Vec<OsString> {
		self.vhost_device_vsock_args_for_bridge_config(&[])
	}

	/// Build arguments for `vhost-device-vsock` using manifest bridge ports.
	#[must_use]
	pub fn vhost_device_vsock_args_for_bridge_config(
		&self,
		bridge_config: &[BridgeConfig],
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let forward_ports = self.vhost_forward_ports(bridge_config);

		vec![
			"--vm".into(),
			format!(
				"guest-cid={},forward-cid={},forward-listen={},socket={}",
				qemu.guest_cid,
				qemu.host_cid,
				format_forward_ports(&forward_ports),
				qemu.vhost_socket_path.display()
			)
			.into(),
		]
	}

	/// Build arguments for QEMU.
	#[must_use]
	pub fn qemu_args(&self) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = vec![
			"-M".into(),
			"nitro-enclave,vsock=c,id=qos-test-harness".into(),
			"-kernel".into(),
			self.spec.eif.path.clone().into_os_string(),
			"-nographic".into(),
			"-m".into(),
			qemu.memory.clone().into(),
		];
		if qemu.enable_kvm {
			args.push("--enable-kvm".into());
		}
		args.extend([
			"-cpu".into(),
			qemu.cpu.clone().into(),
			"-chardev".into(),
			format!("socket,id=c,path={}", qemu.vhost_socket_path.display())
				.into(),
		]);
		args
	}

	/// Build a Docker command for `qos_host`.
	#[must_use]
	pub fn qos_host_docker_args(&self) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.docker_run_prefix(&self.spec.host_run);
		self.spec.host_program.append_program_args(&mut args);
		args.extend([
			"--host-ip".into(),
			qemu.host_ip.clone().into(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--cid".into(),
			qemu.host_cid.to_string().into(),
			"--port".into(),
			qemu.control_vsock_port.to_string().into(),
			"--vsock-to-host".into(),
			"false".into(),
		]);
		args
	}

	/// Build a Docker command for `qos_bridge` ingress.
	#[must_use]
	pub fn qos_bridge_docker_args(&self) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.docker_run_prefix(&self.spec.bridge_run);
		self.spec.bridge_program.append_program_args(&mut args);
		args.extend([
			"--control-url".into(),
			format!("http://{}:{}/qos", qemu.host_connect_ip, qemu.host_port)
				.into(),
			"--cid".into(),
			qemu.host_cid.to_string().into(),
			"--host-port-override".into(),
			qemu.ingress_port.to_string().into(),
			"--vsock-to-host".into(),
			"false".into(),
		]);
		self.append_bridge_egress_bin_path(&mut args);
		args
	}

	fn container_prefix(&self, app_name: &str) -> String {
		format!(
			"qos-test-harness-{}-{}-{}-{}",
			sanitize_name(app_name),
			std::process::id(),
			self.spec.qemu.host_port,
			self.spec.qemu.ingress_port
		)
	}

	async fn start_qemu_guest_runtime(
		&mut self,
		container_prefix: &str,
		bridge_config: &[BridgeConfig],
	) -> Result<(), RunnerError> {
		if self.spec.qemu.qemu_tool_image.is_some() {
			let cleanup_name = format!("{container_prefix}-vhost-cleanup");
			if let Some(args) =
				self.qemu_tool_socket_cleanup_docker_args(&cleanup_name)?
			{
				self.run_docker_args(args)?;
			}
			let vhost_name = format!("{container_prefix}-vhost");
			self.spawn_docker_runtime(
				"vhost-device-vsock",
				vhost_name.clone(),
				self.qemu_tool_docker_args(
					&vhost_name,
					&self.spec.qemu.vhost_device_vsock_bin,
					self.vhost_device_vsock_args_for_tool(bridge_config),
				)?,
			)?;
		} else {
			self.spawn_runtime(
				"vhost-device-vsock",
				&self.spec.qemu.vhost_device_vsock_bin.clone(),
				self.vhost_device_vsock_args_for_bridge_config(bridge_config),
			)?;
		}
		tokio::time::sleep(self.spec.qemu.startup_delay).await;
		self.fail_if_children_exited()?;
		if self.spec.qemu.qemu_tool_image.is_some() {
			let qemu_name = format!("{container_prefix}-qemu");
			self.spawn_docker_runtime(
				"qemu",
				qemu_name.clone(),
				self.qemu_tool_docker_args(
					&qemu_name,
					&self.spec.qemu.qemu_bin,
					self.qemu_args_for_tool(),
				)?,
			)?;
		} else {
			self.spawn_runtime(
				"qemu",
				&self.spec.qemu.qemu_bin.clone(),
				self.qemu_args(),
			)?;
		}
		tokio::time::sleep(self.spec.qemu.startup_delay).await;
		self.fail_if_children_exited()?;
		tokio::time::sleep(self.spec.qemu.guest_boot_delay).await;
		self.fail_if_children_exited()?;
		let host_name = format!("{container_prefix}-host");
		self.spawn_docker_runtime(
			"qos_host",
			host_name.clone(),
			self.qos_host_docker_args_with_name(&host_name),
		)?;
		tokio::time::sleep(self.spec.qemu.startup_delay).await;
		self.fail_if_children_exited()?;
		self.wait_for_qos_ready().await
	}

	/// Build Docker arguments for `qos_client approve-manifest`.
	#[must_use]
	fn approve_manifest_docker_args(
		&self,
		user: &ApprovingUserMaterial,
		workspace: &BootWorkspace,
		manifest: &VersionedManifest,
	) -> Vec<OsString> {
		let boot = &self.spec.boot_fixture;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"approve-manifest".into(),
			"--secret-path".into(),
			self.docker_path(&workspace.user_secret_path(&user.alias))
				.into_os_string(),
			"--manifest-path".into(),
			self.docker_path(&workspace.manifest_path).into_os_string(),
			"--manifest-approvals-dir".into(),
			self.docker_path(&workspace.boot_dir).into_os_string(),
			"--pcr3-preimage-path".into(),
			self.docker_path(&workspace.pcr3_preimage_path).into_os_string(),
			"--pivot-hash-path".into(),
			self.docker_path(&workspace.pivot_hash_path).into_os_string(),
			"--qos-release-dir".into(),
			self.docker_path(&workspace.qos_release_dir).into_os_string(),
			"--manifest-set-dir".into(),
			self.docker_path(&workspace.manifest_set_dir).into_os_string(),
			"--share-set-dir".into(),
			self.docker_path(&workspace.share_set_dir).into_os_string(),
			"--quorum-key-path".into(),
			self.docker_path(&workspace.quorum_key_path).into_os_string(),
			"--alias".into(),
			user.alias.clone().into(),
		]);
		args.extend(manifest_approval_runtime_args(manifest));
		if boot.unsafe_auto_confirm {
			args.push("--unsafe-auto-confirm".into());
		}
		args
	}

	/// Build Docker arguments for `qos_client generate-manifest-envelope`.
	#[must_use]
	fn generate_manifest_envelope_docker_args(
		&self,
		workspace: &BootWorkspace,
	) -> Vec<OsString> {
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"generate-manifest-envelope".into(),
			"--manifest-approvals-dir".into(),
			self.docker_path(&workspace.boot_dir).into_os_string(),
			"--manifest-path".into(),
			self.docker_path(&workspace.manifest_path).into_os_string(),
		]);
		args
	}

	/// Build Docker arguments for `qos_client boot-standard`.
	#[must_use]
	fn boot_standard_docker_args(
		&self,
		pivot: &Pivot,
		workspace: &BootWorkspace,
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let boot = &self.spec.boot_fixture;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"boot-standard".into(),
			"--manifest-envelope-path".into(),
			self.docker_path(&workspace.manifest_envelope_path)
				.into_os_string(),
			"--pivot-path".into(),
			self.docker_path(&pivot.path).into_os_string(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--host-ip".into(),
			qemu.host_connect_ip.clone().into(),
			"--pcr3-preimage-path".into(),
			self.docker_path(&workspace.pcr3_preimage_path).into_os_string(),
		]);
		if boot.unsafe_skip_attestation {
			args.push("--unsafe-skip-attestation".into());
		}
		args
	}

	fn docker_run_prefix(&self, run: &DockerRunSpec) -> Vec<OsString> {
		self.docker_run_prefix_with_name(run, None)
	}

	fn docker_run_prefix_with_name(
		&self,
		run: &DockerRunSpec,
		name: Option<&str>,
	) -> Vec<OsString> {
		let mut args = vec!["run".into(), "--rm".into()];
		if let Some(name) = name {
			args.push("--name".into());
			args.push(name.into());
		}
		if run.privileged {
			args.push("--privileged".into());
		}
		if self.spec.qemu.docker_host_network {
			args.extend(["--network".into(), "host".into()]);
		} else {
			args.extend([
				"--add-host".into(),
				"host.docker.internal:host-gateway".into(),
			]);
		}
		for mount in &run.mounts {
			args.push("--volume".into());
			args.push(mount.to_docker_arg());
		}
		args
	}

	fn qos_client_docker_prefix(&self) -> Vec<OsString> {
		let mut args = self.docker_run_prefix(&self.spec.client_run);
		self.spec.client_program.append_program_args(&mut args);
		args
	}

	fn qos_host_docker_args_with_name(&self, name: &str) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args =
			self.docker_run_prefix_with_name(&self.spec.host_run, Some(name));
		if !qemu.docker_host_network {
			args.extend([
				"--publish".into(),
				format!("{}:{}", qemu.host_port, qemu.host_port).into(),
			]);
		}
		self.spec.host_program.append_program_args(&mut args);
		args.extend([
			"--host-ip".into(),
			qemu.host_ip.clone().into(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--cid".into(),
			qemu.host_cid.to_string().into(),
			"--port".into(),
			qemu.control_vsock_port.to_string().into(),
			"--vsock-to-host".into(),
			"false".into(),
		]);
		args
	}

	fn qos_bridge_docker_args_with_name(&self, name: &str) -> Vec<OsString> {
		self.qos_bridge_docker_args_with_name_and_network(name, None)
	}

	fn qos_bridge_docker_args_with_name_and_network(
		&self,
		name: &str,
		network_container: Option<&str>,
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.docker_run_prefix_with_name_and_network(
			&self.spec.bridge_run,
			name,
			network_container,
		);
		if !qemu.docker_host_network && network_container.is_none() {
			args.extend([
				"--publish".into(),
				format!("{}:{}", qemu.ingress_port, qemu.ingress_port).into(),
			]);
		}
		self.spec.bridge_program.append_program_args(&mut args);
		self.append_qos_bridge_args(&mut args);
		args
	}

	fn append_qos_bridge_args(&self, args: &mut Vec<OsString>) {
		let qemu = &self.spec.qemu;
		args.extend([
			"--control-url".into(),
			format!("http://{}:{}/qos", qemu.host_connect_ip, qemu.host_port)
				.into(),
			"--cid".into(),
			qemu.host_cid.to_string().into(),
			"--host-port-override".into(),
			qemu.ingress_port.to_string().into(),
			"--vsock-to-host".into(),
			"false".into(),
		]);
		self.append_bridge_egress_bin_path(args);
	}

	fn append_bridge_egress_bin_path(&self, args: &mut Vec<OsString>) {
		if let Some(path) = &self.spec.bridge_egress_bin_path {
			args.extend([
				"--egress-bin-path".into(),
				path.clone().into_os_string(),
			]);
		}
	}

	fn docker_run_prefix_with_name_and_network(
		&self,
		run: &DockerRunSpec,
		name: &str,
		network_container: Option<&str>,
	) -> Vec<OsString> {
		let mut args =
			vec!["run".into(), "--rm".into(), "--name".into(), name.into()];
		if run.privileged {
			args.push("--privileged".into());
		}
		if let Some(network_container) = network_container {
			args.extend([
				"--network".into(),
				format!("container:{network_container}").into(),
			]);
		} else if self.spec.qemu.docker_host_network {
			args.extend(["--network".into(), "host".into()]);
		} else {
			args.extend([
				"--add-host".into(),
				"host.docker.internal:host-gateway".into(),
			]);
		}
		for mount in &run.mounts {
			args.push("--volume".into());
			args.push(mount.to_docker_arg());
		}
		args
	}

	fn egress_netns_docker_args_with_name(
		&self,
		name: &str,
	) -> Result<Vec<OsString>, RunnerError> {
		let image =
			self.spec.qemu.egress_setup_image.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
				"qemu.egress_setup_image is required for client egress bridge config"
					.to_string(),
			)
			})?;
		let qemu = &self.spec.qemu;
		let mut args = vec![
			"run".into(),
			"--rm".into(),
			"--name".into(),
			name.into(),
			"--privileged".into(),
		];
		if qemu.docker_host_network {
			args.extend(["--network".into(), "host".into()]);
		} else {
			args.extend([
				"--publish".into(),
				format!("{}:{}", qemu.ingress_port, qemu.ingress_port).into(),
			]);
			args.extend([
				"--add-host".into(),
				"host.docker.internal:host-gateway".into(),
			]);
		}
		args.extend([image.as_str().into(), "sleep".into(), "infinity".into()]);
		Ok(args)
	}

	fn egress_setup_docker_args(
		&self,
		bridge_name: &str,
	) -> Result<Vec<OsString>, RunnerError> {
		let image =
			self.spec.qemu.egress_setup_image.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
				"qemu.egress_setup_image is required for client egress bridge config"
					.to_string(),
			)
			})?;
		let mut args = vec!["run".into(), "--rm".into(), "--privileged".into()];
		args.extend([
			"--network".into(),
			format!("container:{bridge_name}").into(),
			image.as_str().into(),
			"/bin/sh".into(),
			"-c".into(),
			HOST_EGRESS_SETUP_SCRIPT.into(),
		]);
		Ok(args)
	}

	fn egress_checksum_shim_docker_args(
		&self,
		name: &str,
		netns_name: &str,
	) -> Result<Vec<OsString>, RunnerError> {
		let image =
			self.spec.qemu.egress_setup_image.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
				"qemu.egress_setup_image is required for client egress bridge config"
					.to_string(),
			)
			})?;
		Ok(vec![
			"run".into(),
			"--rm".into(),
			"--name".into(),
			name.into(),
			"--privileged".into(),
			"--network".into(),
			format!("container:{netns_name}").into(),
			image.as_str().into(),
			"qos-nfqueue-checksum-fix".into(),
			"--queue".into(),
			HOST_EGRESS_NFQUEUE_NUM.to_string().into(),
		])
	}

	fn docker_path(&self, path: &Path) -> PathBuf {
		self.spec
			.client_run
			.translate_path(path)
			.unwrap_or_else(|| path.to_path_buf())
	}

	fn qemu_tool_path(&self, path: &Path) -> PathBuf {
		if self.spec.qemu.qemu_tool_image.is_some() {
			self.spec
				.qemu
				.docker_tool_run
				.translate_path(path)
				.unwrap_or_else(|| path.to_path_buf())
		} else {
			path.to_path_buf()
		}
	}

	fn qemu_tool_vhost_socket_path(&self) -> PathBuf {
		self.spec
			.qemu
			.qemu_tool_vhost_socket
			.as_ref()
			.map(|socket| socket.socket_path.clone())
			.unwrap_or_else(|| {
				self.qemu_tool_path(&self.spec.qemu.vhost_socket_path)
			})
	}

	fn vhost_device_vsock_args_for_tool(
		&self,
		bridge_config: &[BridgeConfig],
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let forward_ports = self.vhost_forward_ports(bridge_config);

		vec![
			"--vm".into(),
			format!(
				"guest-cid={},forward-cid={},forward-listen={},socket={}",
				qemu.guest_cid,
				qemu.host_cid,
				format_forward_ports(&forward_ports),
				self.qemu_tool_vhost_socket_path().display()
			)
			.into(),
		]
	}

	fn vhost_forward_ports(&self, bridge_config: &[BridgeConfig]) -> Vec<u16> {
		let qemu = &self.spec.qemu;
		let egress_port = qos_core::EGRESS_VSOCK_PORT
			.try_into()
			.expect("QOS egress VSOCK port must fit in u16");
		let mut ports = vec![qemu.control_vsock_port, egress_port];
		for bridge in bridge_config {
			if let BridgeConfig::Server { port, host: _ } = bridge {
				ports.push(*port);
			}
		}
		ports.sort_unstable();
		ports.dedup();
		ports
	}

	fn bridge_config_has_client(bridge_config: &[BridgeConfig]) -> bool {
		bridge_config
			.iter()
			.any(|bridge| matches!(bridge, BridgeConfig::Client { .. }))
	}

	fn qemu_args_for_tool(&self) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = vec![
			"-M".into(),
			"nitro-enclave,vsock=c,id=qos-test-harness".into(),
			"-kernel".into(),
			self.qemu_tool_path(&self.spec.eif.path).into_os_string(),
			"-nographic".into(),
			"-m".into(),
			qemu.memory.clone().into(),
		];
		if qemu.enable_kvm {
			args.push("--enable-kvm".into());
		}
		args.extend([
			"-cpu".into(),
			qemu.cpu.clone().into(),
			"-chardev".into(),
			format!(
				"socket,id=c,path={}",
				self.qemu_tool_vhost_socket_path().display()
			)
			.into(),
		]);
		args
	}

	fn qemu_tool_docker_args(
		&self,
		name: &str,
		bin: &Path,
		tool_args: Vec<OsString>,
	) -> Result<Vec<OsString>, RunnerError> {
		let image =
			self.spec.qemu.qemu_tool_image.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
					"qemu.qemu_tool_image is required for Docker QEMU tools"
						.to_string(),
				)
			})?;
		let mut args = self.docker_run_prefix_with_name(
			&self.spec.qemu.docker_tool_run,
			Some(name),
		);
		if let Some(socket) = &self.spec.qemu.qemu_tool_vhost_socket {
			args.extend(socket.docker_mount_args()?);
		}
		args.push(image.as_str().into());
		args.push(bin.as_os_str().into());
		args.extend(tool_args);
		Ok(args)
	}

	fn qemu_tool_socket_cleanup_docker_args(
		&self,
		name: &str,
	) -> Result<Option<Vec<OsString>>, RunnerError> {
		let Some(socket) = &self.spec.qemu.qemu_tool_vhost_socket else {
			return Ok(None);
		};
		let image =
			self.spec.qemu.qemu_tool_image.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
					"qemu.qemu_tool_image is required for Docker QEMU tools"
						.to_string(),
				)
			})?;
		let mut args = self.docker_run_prefix_with_name(
			&self.spec.qemu.docker_tool_run,
			Some(name),
		);
		args.extend(socket.docker_mount_args()?);
		args.extend([
			image.as_str().into(),
			"/bin/rm".into(),
			"-f".into(),
			socket.socket_path.clone().into_os_string(),
		]);
		Ok(Some(args))
	}

	/// Validate static runner inputs that do not require starting processes.
	pub fn validate_spec(&self) -> Result<(), RunnerError> {
		let qemu = &self.spec.qemu;
		ensure_runner_path("eif.path", &self.spec.eif.path)?;
		ensure_docker_program("host_program", &self.spec.host_program)?;
		ensure_docker_program("bridge_program", &self.spec.bridge_program)?;
		if let Some(path) = &self.spec.bridge_egress_bin_path {
			ensure_runner_path("bridge_egress_bin_path", path)?;
			if !path.is_absolute() {
				return Err(RunnerError::InvalidConfig(
					"bridge_egress_bin_path must be absolute".to_string(),
				));
			}
		}
		ensure_docker_program("client_program", &self.spec.client_program)?;
		if qemu.qemu_tool_image.is_none() {
			ensure_runner_path("qemu.qemu_bin", &qemu.qemu_bin)?;
			ensure_runner_path(
				"qemu.vhost_device_vsock_bin",
				&qemu.vhost_device_vsock_bin,
			)?;
		} else {
			let socket = qemu.qemu_tool_vhost_socket.as_ref().ok_or_else(|| {
				RunnerError::InvalidConfig(
					"qemu.qemu_tool_vhost_socket is required when qemu.qemu_tool_image is configured"
						.to_string(),
				)
			})?;
			if socket.volume_name.trim().is_empty() {
				return Err(RunnerError::InvalidConfig(
					"qemu.qemu_tool_vhost_socket.volume_name may not be empty"
						.to_string(),
				));
			}
			ensure_runner_path(
				"qemu.qemu_tool_vhost_socket.socket_path",
				&socket.socket_path,
			)?;
			if !socket.socket_path.is_absolute() {
				return Err(RunnerError::InvalidConfig(
					"qemu.qemu_tool_vhost_socket.socket_path must be absolute"
						.to_string(),
				));
			}
		}
		ensure_runner_path("qemu.docker_bin", &qemu.docker_bin)?;
		ensure_runner_path("qemu.work_dir", &qemu.work_dir)?;
		ensure_runner_path("qemu.vhost_socket_path", &qemu.vhost_socket_path)?;
		if qemu.host_ip.trim().is_empty() {
			return Err(RunnerError::InvalidConfig(
				"qemu.host_ip may not be empty".to_string(),
			));
		}
		if qemu.host_connect_ip.trim().is_empty() {
			return Err(RunnerError::InvalidConfig(
				"qemu.host_connect_ip may not be empty".to_string(),
			));
		}
		if qemu.ingress_ip.trim().is_empty() {
			return Err(RunnerError::InvalidConfig(
				"qemu.ingress_ip may not be empty".to_string(),
			));
		}
		if qemu.control_vsock_port == 0 {
			return Err(RunnerError::InvalidConfig(
				"qemu.control_vsock_port may not be 0".to_string(),
			));
		}
		if qemu.host_port == 0 {
			return Err(RunnerError::InvalidConfig(
				"qemu.host_port may not be 0".to_string(),
			));
		}
		if qemu.ingress_port == 0 {
			return Err(RunnerError::InvalidConfig(
				"qemu.ingress_port may not be 0".to_string(),
			));
		}
		Ok(())
	}

	/// Build Docker arguments for `qos_client get-attestation-doc`.
	#[must_use]
	fn get_attestation_doc_docker_args(
		&self,
		workspace: &BootWorkspace,
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"get-attestation-doc".into(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--host-ip".into(),
			qemu.host_connect_ip.clone().into(),
			"--attestation-doc-path".into(),
			self.docker_path(&workspace.attestation_doc_path).into_os_string(),
			"--manifest-envelope-path".into(),
			self.docker_path(&workspace.manifest_envelope_path)
				.into_os_string(),
		]);
		args
	}

	/// Build Docker arguments for `qos_client proxy-re-encrypt-share`.
	#[must_use]
	fn proxy_re_encrypt_share_docker_args(
		&self,
		user: &ApprovingUserMaterial,
		workspace: &BootWorkspace,
	) -> Vec<OsString> {
		let boot = &self.spec.boot_fixture;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"proxy-re-encrypt-share".into(),
			"--share-path".into(),
			self.docker_path(&workspace.user_share_path(&user.alias))
				.into_os_string(),
			"--secret-path".into(),
			self.docker_path(&workspace.user_secret_path(&user.alias))
				.into_os_string(),
			"--attestation-doc-path".into(),
			self.docker_path(&workspace.attestation_doc_path).into_os_string(),
			"--eph-wrapped-share-path".into(),
			self.docker_path(&workspace.eph_wrapped_share_path(&user.alias))
				.into_os_string(),
			"--approval-path".into(),
			self.docker_path(&workspace.attestation_approval_path(&user.alias))
				.into_os_string(),
			"--manifest-envelope-path".into(),
			self.docker_path(&workspace.manifest_envelope_path)
				.into_os_string(),
			"--pcr3-preimage-path".into(),
			self.docker_path(&workspace.pcr3_preimage_path).into_os_string(),
			"--manifest-set-dir".into(),
			self.docker_path(&workspace.manifest_set_dir).into_os_string(),
			"--alias".into(),
			user.alias.clone().into(),
		]);
		if boot.unsafe_skip_attestation {
			args.push("--unsafe-skip-attestation".into());
		}
		if boot.unsafe_auto_confirm {
			args.push("--unsafe-auto-confirm".into());
		}
		args
	}

	/// Build Docker arguments for `qos_client post-share`.
	#[must_use]
	fn post_share_docker_args(
		&self,
		user: &ApprovingUserMaterial,
		workspace: &BootWorkspace,
	) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			"post-share".into(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--host-ip".into(),
			qemu.host_connect_ip.clone().into(),
			"--eph-wrapped-share-path".into(),
			self.docker_path(&workspace.eph_wrapped_share_path(&user.alias))
				.into_os_string(),
			"--approval-path".into(),
			self.docker_path(&workspace.attestation_approval_path(&user.alias))
				.into_os_string(),
		]);
		args
	}

	fn spawn_runtime(
		&mut self,
		name: impl Into<String>,
		bin: &Path,
		args: Vec<OsString>,
	) -> Result<(), RunnerError> {
		let name = name.into();
		let child = command_with_args(bin, args)
			.stdin(Stdio::null())
			.spawn()
			.map_err(|err| {
			RunnerError::Command(format!("failed to spawn {name}: {err}"))
		})?;
		self.children.push(ManagedChild {
			name,
			child,
			docker_bin: None,
			docker_container: None,
		});
		Ok(())
	}

	fn spawn_docker_runtime(
		&mut self,
		name: impl Into<String>,
		container_name: impl Into<String>,
		args: Vec<OsString>,
	) -> Result<(), RunnerError> {
		let name = name.into();
		let container_name = container_name.into();
		let child = command_with_args(&self.spec.qemu.docker_bin, args)
			.stdin(Stdio::null())
			.spawn()
			.map_err(|err| {
				RunnerError::Command(format!("failed to spawn {name}: {err}"))
			})?;
		self.children.push(ManagedChild {
			name,
			child,
			docker_bin: Some(self.spec.qemu.docker_bin.clone()),
			docker_container: Some(container_name),
		});
		Ok(())
	}

	fn run_docker_args(&self, args: Vec<OsString>) -> Result<(), RunnerError> {
		run_runner_command(&self.spec.qemu.docker_bin, args)
	}

	async fn run_docker_args_with_retry(
		&mut self,
		label: &str,
		args: Vec<OsString>,
	) -> Result<(), RunnerError> {
		const ATTEMPTS: usize = 3;

		let mut errors = Vec::new();
		for attempt in 1..=ATTEMPTS {
			self.fail_if_children_exited()?;
			match self.run_docker_args(args.clone()) {
				Ok(()) => return Ok(()),
				Err(err) => {
					errors.push(format!(
						"{label} attempt {attempt}/{ATTEMPTS} failed: {err}"
					));
				}
			}
			if attempt != ATTEMPTS {
				tokio::time::sleep(self.spec.qemu.startup_delay).await;
			}
		}

		Err(RunnerError::Command(errors.join("; ")))
	}

	fn run_docker_args_silent(
		&self,
		args: Vec<OsString>,
	) -> Result<bool, RunnerError> {
		let status = command_with_args(&self.spec.qemu.docker_bin, args)
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()?;
		Ok(status.success())
	}

	fn docker_container_exists_args(name: &str) -> Vec<OsString> {
		vec![
			"inspect".into(),
			"--format".into(),
			"{{.State.Running}}".into(),
			name.into(),
		]
	}

	async fn wait_for_docker_container(
		&mut self,
		name: &str,
	) -> Result<(), RunnerError> {
		let start = std::time::Instant::now();
		while start.elapsed() < self.spec.qemu.readiness_timeout {
			self.fail_if_children_exited()?;
			if self.run_docker_args_silent(
				Self::docker_container_exists_args(name),
			)? {
				return Ok(());
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		Err(RunnerError::Command(format!(
			"timed out waiting for docker container {name}"
		)))
	}

	fn qos_client_health_docker_args(&self, command: &str) -> Vec<OsString> {
		let qemu = &self.spec.qemu;
		let mut args = self.qos_client_docker_prefix();
		args.extend([
			command.into(),
			"--host-port".into(),
			qemu.host_port.to_string().into(),
			"--host-ip".into(),
			qemu.host_connect_ip.clone().into(),
		]);
		args
	}

	async fn wait_for_qos_ready(&mut self) -> Result<(), RunnerError> {
		self.wait_for_qos_client_command("host-health").await
	}

	async fn wait_for_qos_client_command(
		&mut self,
		command: &str,
	) -> Result<(), RunnerError> {
		let start = std::time::Instant::now();
		while start.elapsed() < self.spec.qemu.readiness_timeout {
			self.fail_if_children_exited()?;
			if self.run_docker_args_silent(
				self.qos_client_health_docker_args(command),
			)? {
				return Ok(());
			}
			tokio::time::sleep(Duration::from_millis(250)).await;
		}
		Err(RunnerError::Command(format!(
			"timed out waiting for qos_client {command}"
		)))
	}

	fn fail_if_children_exited(&mut self) -> Result<(), RunnerError> {
		for child in &mut self.children {
			match child.child.try_wait() {
				Ok(Some(status)) => {
					return Err(RunnerError::Command(format!(
						"{} exited early with {status}",
						child.name
					)));
				}
				Ok(None) => {}
				Err(err) => {
					return Err(RunnerError::Command(format!(
						"failed to inspect {}: {err}",
						child.name
					)));
				}
			}
		}
		Ok(())
	}

	fn cleanup_children(&mut self) -> Result<(), RunnerError> {
		cleanup_managed_children(&mut self.children)
	}
}

#[derive(Debug)]
struct ManagedChild {
	name: String,
	child: Child,
	docker_bin: Option<PathBuf>,
	docker_container: Option<String>,
}

impl ManagedChild {
	fn stop(&mut self) -> Result<(), String> {
		if let (Some(docker_bin), Some(container)) =
			(&self.docker_bin, &self.docker_container)
		{
			let _ = Command::new(docker_bin)
				.args(["stop", "--timeout", "1", container])
				.status();
		}
		match self.child.try_wait() {
			Ok(Some(_status)) => return Ok(()),
			Ok(None) => {}
			Err(err) => {
				return Err(format!("failed to inspect {}: {err}", self.name));
			}
		}
		self.child
			.kill()
			.map_err(|err| format!("failed to kill {}: {err}", self.name))?;
		self.child.wait().map_err(|err| {
			format!("failed to wait for {}: {err}", self.name)
		})?;
		Ok(())
	}
}

fn cleanup_managed_children(
	children: &mut Vec<ManagedChild>,
) -> Result<(), RunnerError> {
	let mut errors = Vec::new();
	while let Some(mut child) = children.pop() {
		if let Err(err) = child.stop() {
			errors.push(err);
		}
	}
	if errors.is_empty() {
		Ok(())
	} else {
		Err(RunnerError::Command(errors.join("; ")))
	}
}

/// Owned Docker/QEMU app guard.
#[derive(Debug)]
pub struct DockerHostQemuNitroRunningApp {
	app: RunningApp,
	children: Vec<ManagedChild>,
}

impl RunningAppGuard for DockerHostQemuNitroRunningApp {
	fn app(&self) -> &RunningApp {
		&self.app
	}

	async fn stop(mut self) -> Result<(), RunnerError> {
		cleanup_managed_children(&mut self.children)
	}
}

impl Drop for DockerHostQemuNitroRunningApp {
	fn drop(&mut self) {
		drop(cleanup_managed_children(&mut self.children));
	}
}

impl Drop for DockerHostQemuNitroRunner {
	fn drop(&mut self) {
		drop(self.cleanup_children());
	}
}

impl TestRunner for DockerHostQemuNitroRunner {
	type Artifact = Pivot;
	type Running = DockerHostQemuNitroRunningApp;

	async fn start_app(
		&mut self,
		spec: StartAppSpec<Self::Artifact>,
	) -> Result<Self::Running, RunnerError> {
		let result: Result<RunningApp, RunnerError> = async {
			self.validate_spec()?;
			validate_qemu_bridge_config(spec.manifest.bridge_config())?;

			let workspace = BootWorkspace::under(
				self.spec.qemu.work_dir.join(sanitize_name(&spec.name)),
			);
			drop(std::fs::remove_dir_all(&workspace.input_dir));
			drop(std::fs::remove_dir_all(&workspace.boot_dir));
			drop(std::fs::remove_dir_all(&workspace.attestation_dir));
			std::fs::create_dir_all(&workspace.input_dir)?;
			std::fs::create_dir_all(&workspace.boot_dir)?;
			std::fs::create_dir_all(&workspace.attestation_dir)?;
			stage_boot_material(&self.spec.boot_fixture, &workspace)?;
			write_manifest(&spec.manifest, &workspace.manifest_path)?;
			write_file(
				&workspace.pivot_hash_path,
				qos_hex::encode(spec.manifest.pivot_hash()).as_bytes(),
			)?;

			let container_prefix = self.container_prefix(&spec.name);
			self.start_qemu_guest_runtime(
				&container_prefix,
				spec.manifest.bridge_config(),
			)
			.await?;
			for user in &self.spec.boot_fixture.approving_users {
				self.run_docker_args(self.approve_manifest_docker_args(
					user,
					&workspace,
					&spec.manifest,
				))?;
			}
			self.run_docker_args(
				self.generate_manifest_envelope_docker_args(&workspace),
			)?;
			self.run_docker_args_with_retry(
				"qos_client boot-standard",
				self.boot_standard_docker_args(&spec.artifact, &workspace),
			)
			.await?;
			self.run_docker_args(
				self.get_attestation_doc_docker_args(&workspace),
			)?;
			for user in &self.spec.boot_fixture.approving_users {
				self.run_docker_args(
					self.proxy_re_encrypt_share_docker_args(user, &workspace),
				)?;
				self.run_docker_args(
					self.post_share_docker_args(user, &workspace),
				)?;
			}
			tokio::time::sleep(self.spec.qemu.startup_delay).await;
			self.fail_if_children_exited()?;
			let bridge_name = format!("{container_prefix}-bridge");
			if Self::bridge_config_has_client(spec.manifest.bridge_config()) {
				let netns_name = format!("{container_prefix}-egress-netns");
				self.spawn_docker_runtime(
					"egress_netns",
					netns_name.clone(),
					self.egress_netns_docker_args_with_name(&netns_name)?,
				)?;
				self.wait_for_docker_container(&netns_name).await?;
				self.run_docker_args(
					self.egress_setup_docker_args(&netns_name)?,
				)?;
				let checksum_name =
					format!("{container_prefix}-egress-checksum");
				self.spawn_docker_runtime(
					"egress_checksum_shim",
					checksum_name.clone(),
					self.egress_checksum_shim_docker_args(
						&checksum_name,
						&netns_name,
					)?,
				)?;
				self.wait_for_docker_container(&checksum_name).await?;
				self.spawn_docker_runtime(
					"qos_bridge",
					bridge_name.clone(),
					self.qos_bridge_docker_args_with_name_and_network(
						&bridge_name,
						Some(&netns_name),
					),
				)?;
			} else {
				self.spawn_docker_runtime(
					"qos_bridge",
					bridge_name.clone(),
					self.qos_bridge_docker_args_with_name(&bridge_name),
				)?;
			}
			tokio::time::sleep(self.spec.qemu.startup_delay).await;
			self.fail_if_children_exited()?;

			Ok(RunningApp {
				id: spec.name,
				ingress_url: format!(
					"http://{}:{}",
					self.spec.qemu.ingress_ip, self.spec.qemu.ingress_port
				),
			})
		}
		.await;

		match result {
			Ok(app) => Ok(DockerHostQemuNitroRunningApp {
				app,
				children: std::mem::take(&mut self.children),
			}),
			Err(start_error) => match self.cleanup_children() {
				Ok(()) => Err(start_error),
				Err(cleanup_error) => Err(RunnerError::Command(format!(
					"app startup failed: {start_error}; startup cleanup failed: {cleanup_error}"
				))),
			},
		}
	}
}

fn ensure_runner_path(
	name: &'static str,
	path: &Path,
) -> Result<(), RunnerError> {
	if path.as_os_str().is_empty() {
		return Err(RunnerError::InvalidConfig(format!(
			"{name} may not be empty"
		)));
	}
	Ok(())
}

fn ensure_docker_program(
	name: &'static str,
	program: &DockerProgram,
) -> Result<(), RunnerError> {
	if let DockerProgram::MountedBinary { path, .. } = program {
		ensure_runner_path(name, path)?;
		if !path.is_absolute() {
			return Err(RunnerError::InvalidConfig(format!(
				"{name} mounted binary path must be absolute"
			)));
		}
	}
	Ok(())
}

fn validate_qemu_bridge_config(
	bridge_config: &[BridgeConfig],
) -> Result<(), RunnerError> {
	let server_count = bridge_config
		.iter()
		.filter(|bridge| matches!(bridge, BridgeConfig::Server { .. }))
		.count();
	if server_count != 1 {
		return Err(RunnerError::Unsupported(
			"DockerHostQemuNitroRunner currently supports exactly one server ingress bridge config entry"
				.into(),
		));
	}
	Ok(())
}

const HOST_EGRESS_NFQUEUE_NUM: u16 = 100;

const HOST_EGRESS_SETUP_SCRIPT: &str =
	include_str!("../docker/host_egress_setup.sh");

fn format_forward_ports(ports: &[u16]) -> String {
	ports.iter().map(u16::to_string).collect::<Vec<_>>().join("+")
}

fn sanitize_name(name: &str) -> String {
	name.chars()
		.map(|ch| {
			if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
				ch
			} else {
				'_'
			}
		})
		.collect()
}

fn stage_boot_material(
	boot: &BootClientFixture,
	workspace: &BootWorkspace,
) -> Result<(), RunnerError> {
	std::fs::create_dir_all(&workspace.input_dir)?;
	write_file(&workspace.pcr3_preimage_path, &boot.material.pcr3_preimage)?;
	write_file(&workspace.quorum_key_path, &boot.material.quorum_key)?;
	write_material_files(
		&workspace.qos_release_dir,
		&boot.material.qos_release.files,
	)?;
	write_material_files(
		&workspace.manifest_set_dir,
		&boot.material.manifest_set.files,
	)?;
	write_material_files(
		&workspace.share_set_dir,
		&boot.material.share_set.files,
	)?;
	for user in &boot.approving_users {
		if user.alias.trim().is_empty() {
			return Err(RunnerError::InvalidConfig(
				"approving user alias may not be empty".to_string(),
			));
		}
		write_file(&workspace.user_secret_path(&user.alias), &user.secret)?;
		write_file(&workspace.user_share_path(&user.alias), &user.share)?;
	}
	Ok(())
}

fn write_material_files(
	root: &Path,
	files: &[MaterialFile],
) -> Result<(), RunnerError> {
	for file in files {
		validate_material_relative_path(&file.relative_path)?;
		write_file(&root.join(&file.relative_path), &file.contents)?;
	}
	Ok(())
}

fn validate_material_relative_path(path: &Path) -> Result<(), RunnerError> {
	if path.as_os_str().is_empty() || path.is_absolute() {
		return Err(RunnerError::InvalidConfig(format!(
			"material file path must be relative and non-empty: {}",
			path.display()
		)));
	}
	if path.components().any(|component| {
		matches!(
			component,
			std::path::Component::ParentDir
				| std::path::Component::RootDir
				| std::path::Component::Prefix(_)
		)
	}) {
		return Err(RunnerError::InvalidConfig(format!(
			"material file path may not escape its bundle: {}",
			path.display()
		)));
	}
	Ok(())
}

fn write_file(path: &Path, contents: &[u8]) -> Result<(), RunnerError> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(path, contents)?;
	Ok(())
}

fn write_manifest(
	manifest: &VersionedManifest,
	path: &Path,
) -> Result<(), RunnerError> {
	let bytes = manifest.to_storage_vec().map_err(|err| {
		RunnerError::InvalidConfig(format!("serialize manifest: {err}"))
	})?;
	write_file(path, &bytes)
}

fn manifest_approval_runtime_args(
	manifest: &VersionedManifest,
) -> Vec<OsString> {
	let restart = match manifest.restart() {
		RestartPolicy::Never => "never",
		RestartPolicy::Always => "always",
	};
	let mut args = vec![
		"--restart-policy".into(),
		restart.into(),
		"--pivot-args".into(),
		format!("[{}]", manifest.args().join(",")).into(),
		"--bridge-config".into(),
		serde_json::to_string(manifest.bridge_config())
			.expect("bridge configuration is JSON serializable")
			.into(),
		"--debug-mode".into(),
		manifest.debug_mode().to_string().into(),
	];
	if let Some(dns) = manifest.dns_config() {
		args.extend([
			"--dns-resolvers".into(),
			format!(
				"[{}]",
				dns.resolvers
					.iter()
					.map(ToString::to_string)
					.collect::<Vec<_>>()
					.join(",")
			)
			.into(),
		]);
	}
	args
}

fn command_with_args(bin: &Path, args: Vec<OsString>) -> Command {
	let mut command = Command::new(bin);
	command.args(args);
	command
}

fn run_runner_command(
	bin: &Path,
	args: Vec<OsString>,
) -> Result<(), RunnerError> {
	let mut command = command_with_args(bin, args);
	let debug = format!("{command:?}");
	let output = command.output()?;
	if output.status.success() {
		return Ok(());
	}
	Err(RunnerError::Command(format!(
		"command failed: {debug}; status: {}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	)))
}

#[cfg(test)]
mod tests {
	use qos_core::protocol::services::boot::{
		ManifestSet, ManifestVersion, Namespace, NitroConfig, PatchSet,
		RestartPolicy, ShareSet,
	};

	use super::*;
	use crate::{DnsConfig, ManifestBuilder};

	fn manifest(version: ManifestVersion) -> ManifestBuilder {
		ManifestBuilder::new()
			.with_version(version)
			.namespace(Namespace {
				name: "test".into(),
				nonce: 1,
				quorum_key: vec![],
			})
			.pivot_hash([1; 32])
			.restart_policy(RestartPolicy::Always)
			.pivot_args(vec!["--host".into(), "0.0.0.0".into()])
			.bridge_config(vec![BridgeConfig::Server {
				port: 3000,
				host: "0.0.0.0".into(),
			}])
			.debug_mode(true)
			.manifest_set(ManifestSet { threshold: 0, members: vec![] })
			.share_set(ShareSet { threshold: 0, members: vec![] })
			.enclave(NitroConfig {
				pcr0: vec![],
				pcr1: vec![],
				pcr2: vec![],
				pcr3: vec![],
				aws_root_certificate: vec![],
				qos_commit: String::new(),
			})
	}

	#[test]
	fn v1_approval_runtime_args_match_manifest() {
		let manifest = manifest(ManifestVersion::V1)
			.patch_set(PatchSet { threshold: 0, members: vec![] })
			.build()
			.unwrap();

		assert_eq!(
			manifest_approval_runtime_args(&manifest),
			[
				"--restart-policy",
				"always",
				"--pivot-args",
				"[--host,0.0.0.0]",
				"--bridge-config",
				"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
				"--debug-mode",
				"true",
			]
			.map(OsString::from)
		);
	}

	#[test]
	fn v2_approval_runtime_args_include_dns() {
		let manifest = manifest(ManifestVersion::V2)
			.dns(DnsConfig { resolvers: vec!["1.1.1.1".parse().unwrap()] })
			.build()
			.unwrap();

		assert_eq!(
			manifest_approval_runtime_args(&manifest),
			[
				"--restart-policy",
				"always",
				"--pivot-args",
				"[--host,0.0.0.0]",
				"--bridge-config",
				"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
				"--debug-mode",
				"true",
				"--dns-resolvers",
				"[1.1.1.1]",
			]
			.map(OsString::from)
		);
	}
}
