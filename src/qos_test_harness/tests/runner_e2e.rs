use std::{
	net::TcpListener,
	path::{Path, PathBuf},
};

use qos_test_harness::{
	ArtifactBuildPlan, ArtifactBuildRequest, ArtifactBuilder, ArtifactRequest,
	BuildProfile, BuilderKind, HostRunnerKind, RunnerKind,
	SignedEchoTestConfig, runners::docker::DockerRunnerConfig,
	runners::docker::DockerTestRunner,
	runners::nested_nitro::NestedNitroQemuBuilder,
	runners::nested_nitro::NestedNitroQemuConfig,
	runners::nested_nitro::NestedNitroQemuRunner,
	runners::qemu::CargoSignedEchoBuilder, runners::qemu::QemuFlavor,
	runners::qemu::QemuRunnerConfig, runners::qemu::QemuTestRunner,
	signed_echo_startup_shutdown,
};

#[tokio::test(flavor = "multi_thread")]
async fn docker_signed_echo_e2e() {
	if !enabled("QOS_TEST_DOCKER") {
		eprintln!("skipping docker e2e; set QOS_TEST_DOCKER=1 to run");
		return;
	}

	let mut runner = DockerTestRunner::new(DockerRunnerConfig::new(
		workspace_root(),
		port("QOS_TEST_DOCKER_PORT", 39_300),
	));
	signed_echo_startup_shutdown(&mut runner, SignedEchoTestConfig::default())
		.await
		.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn reproducible_qemu_signed_echo_e2e() {
	if !enabled("QOS_TEST_QEMU_REPRODUCIBLE") {
		eprintln!(
			"skipping reproducible qemu e2e; set QOS_TEST_QEMU_REPRODUCIBLE=1 to run"
		);
		return;
	}

	let mut config = QemuRunnerConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_REPRODUCIBLE_APP_PORT", 39_310),
	);
	config.control_port =
		port("QOS_TEST_QEMU_REPRODUCIBLE_CONTROL_PORT", 39_311);
	apply_qemu_env(&mut config, "QOS_TEST_QEMU_REPRODUCIBLE");
	let mut runner = QemuTestRunner::reproducible(config);

	signed_echo_startup_shutdown(&mut runner, SignedEchoTestConfig::default())
		.await
		.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn light_qemu_signed_echo_e2e() {
	if !enabled("QOS_TEST_QEMU_LIGHT") {
		eprintln!("skipping light qemu e2e; set QOS_TEST_QEMU_LIGHT=1 to run");
		return;
	}

	let mut config = QemuRunnerConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_LIGHT_APP_PORT", 39_320),
	);
	config.control_port = port("QOS_TEST_QEMU_LIGHT_CONTROL_PORT", 39_321);
	config.light_core_host_port =
		port("QOS_TEST_QEMU_LIGHT_CORE_HOST_PORT", 39_322);
	apply_qemu_env(&mut config, "QOS_TEST_QEMU_LIGHT");
	config.light_kernel_path =
		std::env::var_os("QOS_TEST_QEMU_LIGHT_KERNEL").map(PathBuf::from);
	if config.light_kernel_path.is_none() {
		panic!("set QOS_TEST_QEMU_LIGHT_KERNEL for plain-kernel light QEMU");
	}
	let mut runner = QemuTestRunner::light(config);

	signed_echo_startup_shutdown(&mut runner, SignedEchoTestConfig::default())
		.await
		.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_nitro_qemu_signed_echo_e2e() {
	if !enabled("QOS_TEST_QEMU_NESTED_NITRO") {
		eprintln!(
			"skipping nested Nitro qemu e2e; set QOS_TEST_QEMU_NESTED_NITRO=1 to run"
		);
		return;
	}

	let mut config = NestedNitroQemuConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_NESTED_NITRO_APP_HOST_PORT", 39_350),
	);
	config.parent_control_port =
		port("QOS_TEST_QEMU_NESTED_NITRO_PARENT_CONTROL_PORT", 39_351);
	config.parent_app_port =
		port("QOS_TEST_QEMU_NESTED_NITRO_PARENT_APP_PORT", 39_352);
	apply_nested_nitro_env(&mut config, "QOS_TEST_QEMU_NESTED_NITRO");
	let mut runner = NestedNitroQemuRunner::new(config);

	signed_echo_startup_shutdown(&mut runner, SignedEchoTestConfig::default())
		.await
		.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn light_qemu_builder_cross_compiles_package() {
	if !enabled("QOS_TEST_QEMU_LIGHT_BUILD") {
		eprintln!(
			"skipping light qemu build; set QOS_TEST_QEMU_LIGHT_BUILD=1 to run"
		);
		return;
	}

	let config = QemuRunnerConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_LIGHT_BUILD_APP_PORT", 39_330),
	);
	let builder =
		CargoSignedEchoBuilder::new(config.clone(), QemuFlavor::Light);
	let output = builder
		.build(&ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: ArtifactRequest::SignedEcho,
				runner: RunnerKind::LightQemu,
				host_runner: HostRunnerKind::Native,
			},
			workspace_root: config.workspace_root,
			output_dir: config.output_dir,
			builder: BuilderKind::LocalCrossCompile,
			profile: BuildProfile::Release,
			target_triple: Some(config.target_triple),
			package: "qos_test_harness".to_string(),
			bin: "signed_echo".to_string(),
			extra_inputs: std::collections::BTreeMap::new(),
		})
		.await
		.unwrap();

	assert!(output.pivot.is_some(), "signed_echo pivot must be built");
	assert!(output.rootfs.is_some(), "light initramfs must be packaged");
	for name in ["qos_core", "light_init", "init"] {
		assert!(
			output.enclave_binaries.iter().any(|binary| binary.name == name),
			"missing enclave binary {name}"
		);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn reproducible_qemu_builder_builds_plain_package() {
	if !enabled("QOS_TEST_QEMU_REPRODUCIBLE_BUILD") {
		eprintln!(
			"skipping reproducible qemu build; set QOS_TEST_QEMU_REPRODUCIBLE_BUILD=1 to run"
		);
		return;
	}

	let mut config = QemuRunnerConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_REPRODUCIBLE_BUILD_APP_PORT", 39_340),
	);
	apply_qemu_env(&mut config, "QOS_TEST_QEMU_REPRODUCIBLE_BUILD");
	let builder =
		CargoSignedEchoBuilder::new(config.clone(), QemuFlavor::Reproducible);
	let output = builder
		.build(&ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: ArtifactRequest::SignedEcho,
				runner: RunnerKind::ReproducibleQemu,
				host_runner: HostRunnerKind::Native,
			},
			workspace_root: config.workspace_root,
			output_dir: config.output_dir,
			builder: BuilderKind::StageX,
			profile: BuildProfile::Release,
			target_triple: Some(config.target_triple),
			package: "qos_test_harness".to_string(),
			bin: "signed_echo".to_string(),
			extra_inputs: std::collections::BTreeMap::new(),
		})
		.await
		.unwrap();

	assert!(output.pivot.is_some(), "signed_echo pivot must be built");
	assert!(output.rootfs.is_some(), "reproducible rootfs must be built");
	assert!(
		output.metadata.contains_key("kernel_path"),
		"reproducible plain QEMU kernel must be recorded"
	);
	for name in ["qos_core", "light_init"] {
		assert!(
			output.enclave_binaries.iter().any(|binary| binary.name == name),
			"missing enclave binary {name}"
		);
	}
	for name in ["qos_host", "qos_client", "qos_bridge"] {
		assert!(
			output.host_binaries.iter().any(|binary| binary.name == name),
			"missing host binary {name}"
		);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_nitro_qemu_builder_stages_parent_rootfs() {
	if !enabled("QOS_TEST_QEMU_NESTED_NITRO_BUILD") {
		eprintln!(
			"skipping nested Nitro qemu build; set QOS_TEST_QEMU_NESTED_NITRO_BUILD=1 to run"
		);
		return;
	}

	let mut config = NestedNitroQemuConfig::new(
		workspace_root(),
		port("QOS_TEST_QEMU_NESTED_NITRO_BUILD_APP_HOST_PORT", 39_360),
	);
	apply_nested_nitro_env(&mut config, "QOS_TEST_QEMU_NESTED_NITRO_BUILD");
	let builder = NestedNitroQemuBuilder::new(config.clone());
	let output = builder
		.build(&ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: ArtifactRequest::SignedEcho,
				runner: RunnerKind::NestedNitroQemu,
				host_runner: HostRunnerKind::Qemu,
			},
			workspace_root: config.workspace_root,
			output_dir: config.output_dir,
			builder: BuilderKind::StageX,
			profile: BuildProfile::Release,
			target_triple: Some(config.enclave_target_triple),
			package: "qos_test_harness".to_string(),
			bin: "signed_echo".to_string(),
			extra_inputs: std::collections::BTreeMap::new(),
		})
		.await
		.unwrap();

	assert!(output.pivot.is_some(), "signed_echo pivot must be built");
	assert!(output.eif.is_some(), "nitro EIF must be built");
	assert!(
		output.metadata.contains_key("parent_rootfs_dir"),
		"parent rootfs dir must be recorded"
	);
	for name in ["nested_parent_init", "qos_host", "qos_client", "qos_bridge"] {
		assert!(
			output.host_binaries.iter().any(|binary| binary.name == name),
			"missing parent binary {name}"
		);
	}
}

fn apply_qemu_env(config: &mut QemuRunnerConfig, prefix: &str) {
	if let Some(path) = env_path(&format!("{prefix}_QEMU_BIN")) {
		config.qemu_bin = path;
	}
	if let Some(path) = env_path(&format!("{prefix}_KERNEL")) {
		config.light_kernel_path = Some(path);
	}
	if let Some(path) = env_path(&format!("{prefix}_TARGET_LINKER")) {
		config.target_linker = Some(path.display().to_string());
	}
	if let Ok(target) = std::env::var(format!("{prefix}_TARGET_TRIPLE")) {
		config.target_triple = target;
	}
	if let Ok(memory) = std::env::var(format!("{prefix}_MEMORY")) {
		config.memory = memory;
	}
	if let Ok(cmdline) = std::env::var(format!("{prefix}_LIGHT_KERNEL_CMDLINE"))
	{
		config.light_kernel_cmdline = cmdline;
	}
	if let Ok(cmdline) = std::env::var(format!("{prefix}_KERNEL_CMDLINE")) {
		config.light_kernel_cmdline = cmdline;
	}
	if let Ok(machine) = std::env::var(format!("{prefix}_LIGHT_MACHINE")) {
		config.light_machine = Some(machine);
	}
	if let Ok(machine) = std::env::var(format!("{prefix}_MACHINE")) {
		config.light_machine = Some(machine);
	}
	if let Ok(cpu) = std::env::var(format!("{prefix}_LIGHT_CPU")) {
		config.light_cpu = Some(cpu);
	}
	if let Ok(cpu) = std::env::var(format!("{prefix}_CPU")) {
		config.light_cpu = Some(cpu);
	}
	if let Ok(net_device) = std::env::var(format!("{prefix}_LIGHT_NET_DEVICE"))
	{
		config.light_net_device = net_device;
	}
	if let Ok(net_device) = std::env::var(format!("{prefix}_NET_DEVICE")) {
		config.light_net_device = net_device;
	}
	if let Some(use_9p_rootfs) =
		env_bool(&format!("{prefix}_LIGHT_USE_9P_ROOTFS"))
	{
		config.light_use_9p_rootfs = use_9p_rootfs;
	}
	if let Some(use_9p_rootfs) = env_bool(&format!("{prefix}_USE_9P_ROOTFS")) {
		config.light_use_9p_rootfs = use_9p_rootfs;
	}
	if let Some(enable_kvm) = env_bool(&format!("{prefix}_ENABLE_KVM")) {
		config.enable_kvm = enable_kvm;
	}
	if let Ok(value) =
		std::env::var(format!("{prefix}_LIGHT_GUEST_CONTROL_PORT"))
		&& let Ok(port) = value.parse()
	{
		config.light_guest_control_port = port;
	}
	if let Ok(value) = std::env::var(format!("{prefix}_GUEST_CONTROL_PORT"))
		&& let Ok(port) = value.parse()
	{
		config.light_guest_control_port = port;
	}
}

fn apply_nested_nitro_env(config: &mut NestedNitroQemuConfig, prefix: &str) {
	if let Some(path) = env_path(&format!("{prefix}_OUTER_QEMU_BIN")) {
		config.outer_qemu_bin = path;
	}
	if let Some(path) = env_path(&format!("{prefix}_QEMU_BIN")) {
		config.outer_qemu_bin = path;
	}
	if let Some(path) = env_path(&format!("{prefix}_OUTER_KERNEL")) {
		config.outer_kernel_path = Some(path);
	}
	if let Some(path) = env_path(&format!("{prefix}_KERNEL")) {
		config.outer_kernel_path = Some(path);
	}
	if let Some(path) = env_path(&format!("{prefix}_PARENT_OVERLAY")) {
		config.parent_overlay_dir = Some(path);
	}
	if let Some(path) = env_path(&format!("{prefix}_PARENT_TARGET_LINKER")) {
		config.parent_target_linker = Some(path.display().to_string());
	}
	if let Some(path) = env_path(&format!("{prefix}_ENCLAVE_TARGET_LINKER")) {
		config.enclave_target_linker = Some(path.display().to_string());
	}
	if let Ok(target) = std::env::var(format!("{prefix}_PARENT_TARGET_TRIPLE"))
	{
		config.parent_target_triple = target;
	}
	if let Ok(target) = std::env::var(format!("{prefix}_ENCLAVE_TARGET_TRIPLE"))
	{
		config.enclave_target_triple = target;
	}
	if let Ok(cmdline) = std::env::var(format!("{prefix}_OUTER_KERNEL_CMDLINE"))
	{
		config.outer_kernel_cmdline = cmdline;
	}
	if let Ok(machine) = std::env::var(format!("{prefix}_OUTER_MACHINE")) {
		config.outer_machine = machine;
	}
	if let Ok(accel) = std::env::var(format!("{prefix}_OUTER_ACCEL")) {
		config.outer_accel = if matches!(accel.as_str(), "" | "none" | "NONE") {
			None
		} else {
			Some(accel)
		};
	}
	if let Ok(cpu) = std::env::var(format!("{prefix}_OUTER_CPU")) {
		config.outer_cpu = if matches!(cpu.as_str(), "" | "none" | "NONE") {
			None
		} else {
			Some(cpu)
		};
	}
	if let Ok(net_device) = std::env::var(format!("{prefix}_OUTER_NET_DEVICE"))
	{
		config.outer_net_device = net_device;
	}
	if let Ok(memory) = std::env::var(format!("{prefix}_OUTER_MEMORY")) {
		config.outer_memory = memory;
	}
	if let Ok(memory) = std::env::var(format!("{prefix}_INNER_MEMORY")) {
		config.inner_memory = memory;
	}
	if let Ok(path) = std::env::var(format!("{prefix}_PARENT_QEMU_PATH")) {
		config.parent_qemu_path = path;
	}
	if let Ok(path) = std::env::var(format!("{prefix}_PARENT_VHOST_VSOCK_PATH"))
	{
		config.parent_vhost_vsock_path = path;
	}
	if let Ok(path) = std::env::var(format!("{prefix}_VHOST_SOCKET_PATH")) {
		config.vhost_socket_path = path;
	}
	if let Ok(id) = std::env::var(format!("{prefix}_INNER_QEMU_ID")) {
		config.inner_qemu_id = id;
	}
	if let Ok(host) = std::env::var(format!("{prefix}_HOST")) {
		config.host = host;
	}
	if let Some(port) = env_u16(&format!("{prefix}_APP_HOST_PORT")) {
		config.app_host_port = port;
	}
	if let Some(port) = env_u16(&format!("{prefix}_PARENT_CONTROL_PORT")) {
		config.parent_control_port = port;
	}
	if let Some(port) = env_u16(&format!("{prefix}_PARENT_APP_PORT")) {
		config.parent_app_port = port;
	}
	if let Some(cid) = env_u32(&format!("{prefix}_NESTED_GUEST_CID")) {
		config.nested_guest_cid = cid;
	}
	if let Some(cid) = env_u32(&format!("{prefix}_NESTED_FORWARD_CID")) {
		config.nested_forward_cid = cid;
	}
	if let Some(port) = env_u32(&format!("{prefix}_NESTED_CORE_PORT")) {
		config.nested_core_port = port;
	}
	if let Some(value) = env_bool(&format!("{prefix}_HOST_VSOCK_TO_HOST")) {
		config.host_vsock_to_host = value;
	}
	if let Some(value) = env_bool(&format!("{prefix}_BRIDGE_VSOCK_TO_HOST")) {
		config.bridge_vsock_to_host = value;
	}
	if let Some(value) = env_bool(&format!("{prefix}_KEEP_ON_FAILURE")) {
		config.keep_on_failure = value;
	}
}

fn enabled(name: &str) -> bool {
	std::env::var(name).is_ok_and(|value| {
		matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
	})
}

fn workspace_root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.canonicalize()
		.expect("workspace root should resolve")
}

fn env_path(name: &str) -> Option<PathBuf> {
	std::env::var_os(name).map(PathBuf::from)
}

fn env_bool(name: &str) -> Option<bool> {
	std::env::var(name).ok().map(|value| {
		matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
	})
}

fn env_u16(name: &str) -> Option<u16> {
	std::env::var(name).ok().and_then(|value| value.parse().ok())
}

fn env_u32(name: &str) -> Option<u32> {
	std::env::var(name).ok().and_then(|value| value.parse().ok())
}

fn port(env_name: &str, fallback: u16) -> u16 {
	if let Some(port) =
		std::env::var(env_name).ok().and_then(|value| value.parse().ok())
	{
		return port;
	}

	match TcpListener::bind(("127.0.0.1", 0)) {
		Ok(listener) => listener
			.local_addr()
			.expect("free port should have local addr")
			.port(),
		Err(err) => {
			eprintln!(
				"could not probe free port for {env_name}: {err}; using fallback {fallback}"
			);
			fallback
		}
	}
}
