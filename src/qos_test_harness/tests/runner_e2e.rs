use std::{
	net::TcpListener,
	path::{Path, PathBuf},
};

use qos_test_harness::{
	ArtifactBuildPlan, ArtifactBuildRequest, ArtifactBuilder, ArtifactRequest,
	BuildProfile, BuilderKind, HostRunnerKind, RunnerKind,
	SignedEchoTestConfig, runners::docker::DockerRunnerConfig,
	runners::docker::DockerTestRunner, runners::qemu::CargoSignedEchoBuilder,
	runners::qemu::QemuFlavor, runners::qemu::QemuRunnerConfig,
	runners::qemu::QemuTestRunner, signed_echo_startup_shutdown,
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
