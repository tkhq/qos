//! OCI runtime configuration and upstream `libcontainer` lifecycle adapter.

use std::{
	collections::HashSet,
	ffi::c_void,
	fs::{self, File},
	io::{BufRead, BufReader, Read},
	os::fd::OwnedFd,
	os::unix::fs::PermissionsExt,
	os::unix::net::UnixStream,
	path::{Path, PathBuf},
	thread,
	time::Duration,
};

#[cfg(feature = "oci-devices")]
use std::os::fd::{AsRawFd, FromRawFd};

use libcontainer::{
	container::{Container, builder::ContainerBuilder},
	oci_spec::runtime::{
		Capabilities, Capability, LinuxBuilder, LinuxCapabilitiesBuilder,
		LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxNamespaceBuilder,
		LinuxNamespaceType, LinuxResourcesBuilder, Mount, MountBuilder,
		ProcessBuilder, RootBuilder, Spec, SpecBuilder, UserBuilder,
		get_default_maskedpaths, get_default_readonly_paths,
	},
	syscall::syscall::SyscallType,
};

use crate::{oci_bundle::RuntimeProcess, protocol::services::boot::OciName};

const OCI_RUNTIME_VERSION: &str = "1.0.2";
const SANDBOX_ID: &str = "qos-sandbox";
const SANDBOX_ARG: &str = "--qos-oci-sandbox";
const SANDBOX_READY: &str = "/qos-sandbox-ready";
const MAX_LOG_CHUNK_BYTES: u64 = 16 * 1024;

#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;

/// Error returned by QOS-owned bundle or container lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum OciRuntimeError {
	/// Runtime filesystem operation failed.
	#[error("OCI runtime filesystem operation failed: {0}")]
	Io(#[from] std::io::Error),
	/// Runtime configuration could not be built.
	#[error("invalid QOS OCI runtime configuration: {0}")]
	Config(String),
	/// Upstream `libcontainer` operation failed.
	#[error("libcontainer operation failed: {0}")]
	Libcontainer(String),
	/// One or more required cleanup operations failed.
	#[error("OCI runtime cleanup failed: {0}")]
	Cleanup(String),
}

/// A validated shared namespace path set owned by the QOS sandbox.
#[derive(Debug, Clone)]
pub struct SandboxNamespaces {
	/// Network namespace path.
	pub network: PathBuf,
	/// IPC namespace path.
	pub ipc: PathBuf,
	/// UTS namespace path.
	pub uts: PathBuf,
	/// Parent-owned tmpfs shared by all workloads at `/dev/shm`.
	pub shm: PathBuf,
}

/// One QOS-resolved mount. No path or option comes from an OCI image.
#[derive(Debug, Clone)]
pub struct ResolvedMount {
	/// Parent-QOS source path or pinned `/proc/self/fd` path.
	pub source: PathBuf,
	/// Absolute path inside the workload.
	pub destination: PathBuf,
	/// Whether this is a regular-file bind mount.
	pub file: bool,
	/// Whether the bind mount is read-only.
	pub read_only: bool,
}

/// Exact process termination representation required by Manifest V3 status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
	/// Process called `_exit` or returned with this exact code.
	ExitCode(i32),
	/// Process was terminated by this signal number.
	Signal(i32),
}

/// A created upstream container and its workload-scoped log drains.
pub struct RuntimeContainer {
	container: Container,
	log_threads: Vec<thread::JoinHandle<()>>,
}

impl RuntimeContainer {
	/// Create a detached container from a QOS-generated bundle.
	///
	/// # Errors
	///
	/// Returns an error when descriptors or the upstream container cannot be created.
	pub fn create(
		name: &OciName,
		bundle: &Path,
		state_root: &Path,
	) -> Result<Self, OciRuntimeError> {
		Self::create_id(name.as_str(), name.as_str(), bundle, state_root)
	}

	fn create_id(
		id: &str,
		cgroup_name: &str,
		bundle: &Path,
		state_root: &Path,
	) -> Result<Self, OciRuntimeError> {
		fs::create_dir_all(state_root)?;
		let (stdout_read, stdout_write) = pipe()?;
		let (stderr_read, stderr_write) = pipe()?;
		let stdin = File::open("/dev/null")?;
		let mut container =
			ContainerBuilder::new(id.to_owned(), SyscallType::Linux)
				.validate_id()
				.map_err(runtime_error)?
				.with_root_path(state_root)
				.map_err(runtime_error)?
				.with_stdin(OwnedFd::from(stdin))
				.with_stdout(stdout_write)
				.with_stderr(stderr_write)
				.as_init(bundle)
				.with_systemd(false)
				.with_no_pivot(true)
				.with_detach(true)
				.build()
				.map_err(runtime_error)?;
		if let Err(error) = apply_device_policy(cgroup_name) {
			return match container.delete(true) {
				Ok(()) => Err(error),
				Err(cleanup) => Err(OciRuntimeError::Cleanup(format!(
					"{error}; failed to delete partial container: {cleanup}"
				))),
			};
		}
		let log_threads = vec![
			drain_log(id, "OUT", stdout_read),
			drain_log(id, "ERR", stderr_read),
		];
		Ok(Self { container, log_threads })
	}

	/// Start the application process and return its parent-namespace PID.
	///
	/// # Errors
	///
	/// Returns an error when upstream start fails or does not expose a PID.
	#[allow(clippy::redundant_closure_for_method_calls)]
	pub fn start(&mut self) -> Result<i32, OciRuntimeError> {
		self.container.start().map_err(runtime_error)?;
		self.container.pid().map(|pid| pid.as_raw()).ok_or_else(|| {
			OciRuntimeError::Libcontainer("missing init PID".into())
		})
	}

	/// Wait for the container init process without collapsing signals into an
	/// artificial exit code.
	///
	/// # Errors
	///
	/// Returns an error when the recorded PID cannot be waited.
	#[allow(clippy::redundant_closure_for_method_calls)]
	pub fn wait(&mut self) -> Result<Termination, OciRuntimeError> {
		let pid =
			self.container.pid().map(|pid| pid.as_raw()).ok_or_else(|| {
				OciRuntimeError::Libcontainer("missing init PID".into())
			})?;
		wait_pid(pid)
	}

	/// Send a raw Linux signal to the container init process.
	///
	/// # Errors
	///
	/// Returns an error when the container has no PID or signaling fails.
	#[allow(unsafe_code)]
	#[allow(clippy::redundant_closure_for_method_calls)]
	pub fn signal(&self, signal: i32) -> Result<(), OciRuntimeError> {
		let pid =
			self.container.pid().map(|pid| pid.as_raw()).ok_or_else(|| {
				OciRuntimeError::Libcontainer("missing init PID".into())
			})?;
		// SAFETY: kill only reads its scalar arguments. The PID came from the
		// container state and the signal was validated from image metadata.
		signal_pid(pid, signal)
	}

	/// Force-delete runtime state. This is idempotent when state is already
	/// absent.
	///
	/// # Errors
	///
	/// Returns an error when upstream deletion fails.
	pub fn delete(self) -> Result<(), OciRuntimeError> {
		let Self { mut container, log_threads } = self;
		let mut errors = Vec::new();
		record_error(
			&mut errors,
			container.delete(true).map_err(runtime_error),
		);
		// Release every runtime-owned pipe descriptor before waiting for the
		// collectors, including when a container failed before it was started.
		drop(container);
		for log_thread in log_threads {
			if log_thread.join().is_err() {
				errors.push("container log collector panicked".into());
			}
		}
		if errors.is_empty() {
			Ok(())
		} else {
			Err(OciRuntimeError::Cleanup(errors.join("; ")))
		}
	}
}

/// Internal container that owns the shared workload-group namespaces.
pub struct RuntimeSandbox {
	container: RuntimeContainer,
	root: PathBuf,
	pid: i32,
	/// Namespace paths and shared-memory mount used by workload specs.
	pub namespaces: SandboxNamespaces,
}

impl RuntimeSandbox {
	/// Create and start the QOS-owned namespace sandbox.
	///
	/// # Errors
	///
	/// Returns an error when sandbox setup or required namespaces fail.
	pub fn create(runtime_root: &Path) -> Result<Self, OciRuntimeError> {
		let root = runtime_root.join("sandbox");
		let bundle = root.join("bundle");
		let rootfs = bundle.join("rootfs");
		let state = root.join("state");
		let shm = runtime_root.join("shm");
		fs::create_dir_all(&rootfs)?;
		create_tmpfs(&shm, 0o1777, true)?;
		let executable = std::env::current_exe()?;
		let mode = fs::metadata(&executable)?.permissions().mode();
		fs::set_permissions(
			&executable,
			fs::Permissions::from_mode(mode | 0o001),
		)?;
		let sandbox_executable = rootfs.join("qos-sandbox");
		File::create(&sandbox_executable)?;
		let spec = sandbox_spec(&rootfs, &executable, &shm)?;
		spec.save(bundle.join("config.json"))
			.map_err(|error| OciRuntimeError::Config(error.to_string()))?;
		let mut container = RuntimeContainer::create_id(
			SANDBOX_ID, "sandbox", &bundle, &state,
		)?;
		let pid = match container.start() {
			Ok(pid) => pid,
			Err(error) => {
				return Err(cleanup_partial_sandbox(
					container, &shm, error, false,
				));
			}
		};
		let ready = rootfs.join(SANDBOX_READY.trim_start_matches('/'));
		for _ in 0..100 {
			if ready.exists() {
				break;
			}
			thread::sleep(Duration::from_millis(1));
		}
		if !ready.exists() {
			return Err(cleanup_partial_sandbox(
				container,
				&shm,
				OciRuntimeError::Config("sandbox did not become ready".into()),
				true,
			));
		}
		let namespaces = SandboxNamespaces {
			network: PathBuf::from(format!("/proc/{pid}/ns/net")),
			ipc: PathBuf::from(format!("/proc/{pid}/ns/ipc")),
			uts: PathBuf::from(format!("/proc/{pid}/ns/uts")),
			shm,
		};
		for namespace in [&namespaces.network, &namespaces.ipc, &namespaces.uts]
		{
			if !namespace.exists() {
				return Err(cleanup_partial_sandbox(
					container,
					&namespaces.shm,
					OciRuntimeError::Config(
						"sandbox namespace is unavailable".into(),
					),
					true,
				));
			}
		}
		Ok(Self { container, root, pid, namespaces })
	}

	/// Return whether the sandbox process and required namespace handles exist.
	#[must_use]
	pub fn is_alive(&self) -> bool {
		sandbox_alive(self.pid, &self.namespaces)
	}

	/// Return the immutable values needed by the sandbox supervisor.
	#[must_use]
	pub fn health_handle(&self) -> (i32, SandboxNamespaces) {
		(self.pid, self.namespaces.clone())
	}

	/// Stop the sandbox after all workloads release their namespace refs.
	///
	/// # Errors
	///
	/// Returns an error containing every failed cleanup stage.
	pub fn delete(mut self) -> Result<(), OciRuntimeError> {
		let mut errors = Vec::new();
		record_error(&mut errors, self.container.signal(libc::SIGKILL));
		record_error(&mut errors, self.container.wait());
		record_error(&mut errors, self.container.delete());
		record_error(&mut errors, unmount_path(&self.namespaces.shm));
		if self.root.exists()
			&& let Err(error) = fs::remove_dir_all(self.root)
		{
			errors.push(error.to_string());
		}
		if errors.is_empty() {
			Ok(())
		} else {
			Err(OciRuntimeError::Cleanup(errors.join("; ")))
		}
	}
}

fn cleanup_partial_sandbox(
	mut container: RuntimeContainer,
	shm: &Path,
	cause: OciRuntimeError,
	started: bool,
) -> OciRuntimeError {
	let mut errors = Vec::new();
	if started {
		record_error(&mut errors, container.signal(libc::SIGKILL));
		record_error(&mut errors, container.wait());
	}
	record_error(&mut errors, container.delete());
	record_error(&mut errors, unmount_path(shm));
	if errors.is_empty() {
		cause
	} else {
		OciRuntimeError::Cleanup(format!("{cause}; {}", errors.join("; ")))
	}
}

/// Enter the internal sandbox process mode when requested by QOS.
#[must_use]
pub fn run_sandbox_if_requested() -> bool {
	if std::env::args().nth(1).as_deref() != Some(SANDBOX_ARG) {
		return false;
	}
	if let Err(error) = configure_loopback() {
		eprintln!("failed to configure OCI sandbox loopback: {error}");
		return true;
	}
	if let Err(error) = fs::write(SANDBOX_READY, []) {
		eprintln!("failed to signal OCI sandbox readiness: {error}");
		return true;
	}
	loop {
		// SAFETY: pause has no pointer arguments and waits for a signal.
		#[allow(unsafe_code)]
		unsafe {
			libc::pause();
		}
	}
}

/// Write a complete QOS-owned `config.json` for one workload bundle.
///
/// # Errors
///
/// Returns an error when the configuration cannot be built or persisted.
pub fn write_config(
	bundle: &Path,
	rootfs: &Path,
	process: &RuntimeProcess,
	sandbox: &SandboxNamespaces,
	mounts: &[ResolvedMount],
	name: &OciName,
) -> Result<(), OciRuntimeError> {
	let spec = workload_spec(rootfs, process, sandbox, mounts, name)?;
	spec.save(bundle.join("config.json"))
		.map_err(|error| OciRuntimeError::Config(error.to_string()))
}

fn workload_spec(
	rootfs: &Path,
	process: &RuntimeProcess,
	sandbox: &SandboxNamespaces,
	declared_mounts: &[ResolvedMount],
	name: &OciName,
) -> Result<Spec, OciRuntimeError> {
	let user = UserBuilder::default()
		.uid(process.identity.uid)
		.gid(process.identity.gid)
		.umask(0o022_u32)
		.additional_gids(process.identity.additional_gids.clone())
		.build()
		.map_err(config_error)?;
	let capabilities = capabilities(process.identity.uid == 0)?;
	let process = ProcessBuilder::default()
		.terminal(false)
		.user(user)
		.args(process.args.clone())
		.env(process.env.clone())
		.cwd(process.cwd.clone())
		.capabilities(capabilities)
		.no_new_privileges(true)
		.build()
		.map_err(config_error)?;
	let root = RootBuilder::default()
		.path(rootfs)
		.readonly(false)
		.build()
		.map_err(config_error)?;
	let linux = LinuxBuilder::default()
		.namespaces(namespaces(sandbox)?)
		.resources(device_resources()?)
		.cgroups_path(PathBuf::from("qos").join(name.as_str()))
		.rootfs_propagation("private")
		.masked_paths(get_default_maskedpaths())
		.readonly_paths(get_default_readonly_paths())
		.build()
		.map_err(config_error)?;
	SpecBuilder::default()
		.version(OCI_RUNTIME_VERSION)
		.root(root)
		.mounts(runtime_mounts(sandbox, declared_mounts)?)
		.process(process)
		.hostname("qos")
		.linux(linux)
		.build()
		.map_err(config_error)
}

fn sandbox_spec(
	rootfs: &Path,
	executable: &Path,
	shm: &Path,
) -> Result<Spec, OciRuntimeError> {
	let set: Capabilities = [Capability::NetAdmin].into_iter().collect();
	let capabilities = LinuxCapabilitiesBuilder::default()
		.bounding(set.clone())
		.effective(set.clone())
		.inheritable(set.clone())
		.permitted(set.clone())
		.ambient(set)
		.build()
		.map_err(config_error)?;
	let user = UserBuilder::default()
		.uid(0_u32)
		.gid(0_u32)
		.umask(0o022_u32)
		.build()
		.map_err(config_error)?;
	let process = ProcessBuilder::default()
		.terminal(false)
		.user(user)
		.args(vec!["/qos-sandbox".into(), SANDBOX_ARG.into()])
		.env(vec!["PATH=/usr/sbin:/usr/bin:/sbin:/bin".into()])
		.cwd(PathBuf::from("/"))
		.capabilities(capabilities)
		.no_new_privileges(true)
		.build()
		.map_err(config_error)?;
	let namespaces = [
		LinuxNamespaceType::Pid,
		LinuxNamespaceType::Mount,
		LinuxNamespaceType::Cgroup,
		LinuxNamespaceType::Network,
		LinuxNamespaceType::Ipc,
		LinuxNamespaceType::Uts,
	]
	.into_iter()
	.map(|typ| {
		LinuxNamespaceBuilder::default().typ(typ).build().map_err(config_error)
	})
	.collect::<Result<Vec<_>, _>>()?;
	let linux = LinuxBuilder::default()
		.namespaces(namespaces)
		.resources(device_resources()?)
		.cgroups_path("qos/sandbox")
		.rootfs_propagation("private")
		.masked_paths(get_default_maskedpaths())
		.readonly_paths(get_default_readonly_paths())
		.build()
		.map_err(config_error)?;
	let mounts = vec![
		mount("proc", "/proc", "proc", ["nosuid", "noexec", "nodev"]),
		mount(
			"tmpfs",
			"/dev",
			"tmpfs",
			["nosuid", "strictatime", "mode=755", "size=65536k"],
		),
		bind_mount(shm, Path::new("/dev/shm"), false, false),
		bind_mount(executable, Path::new("/qos-sandbox"), true, false),
	]
	.into_iter()
	.collect::<Result<Vec<_>, _>>()?;
	let root = RootBuilder::default()
		.path(rootfs)
		.readonly(false)
		.build()
		.map_err(config_error)?;
	SpecBuilder::default()
		.version(OCI_RUNTIME_VERSION)
		.root(root)
		.mounts(mounts)
		.process(process)
		.hostname("qos")
		.linux(linux)
		.build()
		.map_err(config_error)
}

fn capabilities(
	root: bool,
) -> Result<libcontainer::oci_spec::runtime::LinuxCapabilities, OciRuntimeError>
{
	use Capability::{
		AuditWrite, Chown, DacOverride, Fowner, Fsetid, Kill, Mknod,
		NetBindService, NetRaw, Setfcap, Setgid, Setpcap, Setuid, SysChroot,
	};
	let bounding: Capabilities = [
		AuditWrite,
		Chown,
		DacOverride,
		Fowner,
		Fsetid,
		Kill,
		Mknod,
		NetBindService,
		NetRaw,
		Setfcap,
		Setgid,
		Setpcap,
		Setuid,
		SysChroot,
	]
	.into_iter()
	.collect();
	let active = if root { bounding.clone() } else { HashSet::new() };
	LinuxCapabilitiesBuilder::default()
		.bounding(bounding)
		.effective(active.clone())
		.inheritable(active.clone())
		.permitted(active.clone())
		.ambient(active)
		.build()
		.map_err(config_error)
}

fn namespaces(
	sandbox: &SandboxNamespaces,
) -> Result<Vec<libcontainer::oci_spec::runtime::LinuxNamespace>, OciRuntimeError>
{
	let new = |typ| {
		LinuxNamespaceBuilder::default().typ(typ).build().map_err(config_error)
	};
	let shared = |typ, path: &Path| {
		LinuxNamespaceBuilder::default()
			.typ(typ)
			.path(path)
			.build()
			.map_err(config_error)
	};
	Ok(vec![
		new(LinuxNamespaceType::Pid)?,
		new(LinuxNamespaceType::Mount)?,
		new(LinuxNamespaceType::Cgroup)?,
		shared(LinuxNamespaceType::Network, &sandbox.network)?,
		shared(LinuxNamespaceType::Ipc, &sandbox.ipc)?,
		shared(LinuxNamespaceType::Uts, &sandbox.uts)?,
	])
}

fn device_resources()
-> Result<libcontainer::oci_spec::runtime::LinuxResources, OciRuntimeError> {
	LinuxResourcesBuilder::default()
		.devices(device_rules()?)
		.build()
		.map_err(config_error)
}

fn device_rules() -> Result<
	Vec<libcontainer::oci_spec::runtime::LinuxDeviceCgroup>,
	OciRuntimeError,
> {
	let mut devices = Vec::new();
	for (major, minor) in
		[(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0), (5, 2)]
	{
		devices.push(device_rule(major, Some(minor))?);
	}
	devices.push(device_rule(136, None)?);
	Ok(devices)
}

#[cfg(feature = "oci-devices")]
#[allow(unsafe_code)]
fn apply_device_policy(cgroup_name: &str) -> Result<(), OciRuntimeError> {
	let cgroup = File::open(Path::new("/sys/fs/cgroup/qos").join(cgroup_name))?;
	raise_memlock_limit()?;
	let instructions = device_program();
	let license = b"GPL\0";
	let mut verifier_log = vec![0_u8; 64 * 1024];
	let mut load = BpfProgLoad {
		prog_type: 15,
		insn_cnt: instructions.len().try_into().map_err(|_| {
			OciRuntimeError::Config("device program is too large".into())
		})?,
		insns: instructions.as_ptr() as u64,
		license: license.as_ptr() as u64,
		log_level: 1,
		log_size: verifier_log.len().try_into().map_err(|_| {
			OciRuntimeError::Config("BPF verifier log is too large".into())
		})?,
		log_buf: verifier_log.as_mut_ptr() as u64,
		expected_attach_type: 6,
		..BpfProgLoad::default()
	};
	// SAFETY: the kernel only reads the initialized attribute and buffers.
	let fd = unsafe {
		libc::syscall(
			libc::SYS_bpf,
			5_u32,
			&raw mut load,
			std::mem::size_of::<BpfProgLoad>(),
		)
	};
	if fd < 0 {
		return Err(OciRuntimeError::Config(format!(
			"BPF_PROG_LOAD failed: {}; verifier: {}",
			std::io::Error::last_os_error(),
			String::from_utf8_lossy(&verifier_log).trim_end_matches('\0')
		)));
	}
	let program_fd = i32::try_from(fd).map_err(|_| {
		OciRuntimeError::Config("BPF program descriptor exceeds range".into())
	})?;
	// SAFETY: BPF_PROG_LOAD returned ownership of this descriptor.
	let program = unsafe { OwnedFd::from_raw_fd(program_fd) };
	let mut attach = BpfProgAttach {
		target_fd: cgroup.as_raw_fd().try_into().map_err(|_| {
			OciRuntimeError::Config("invalid cgroup descriptor".into())
		})?,
		attach_bpf_fd: program.as_raw_fd().try_into().map_err(|_| {
			OciRuntimeError::Config("invalid BPF program descriptor".into())
		})?,
		attach_type: 6,
		attach_flags: 0,
		replace_bpf_fd: 0,
	};
	// SAFETY: the kernel reads the initialized attach attribute.
	if unsafe {
		libc::syscall(
			libc::SYS_bpf,
			8_u32,
			&raw mut attach,
			std::mem::size_of::<BpfProgAttach>(),
		)
	} < 0
	{
		return Err(OciRuntimeError::Config(format!(
			"BPF_PROG_ATTACH failed: {}",
			std::io::Error::last_os_error()
		)));
	}
	Ok(())
}

#[cfg(feature = "oci-devices")]
#[allow(unsafe_code)]
fn raise_memlock_limit() -> Result<(), OciRuntimeError> {
	let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
	// SAFETY: limit points to writable storage for both scalar syscalls.
	if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } < 0 {
		return Err(OciRuntimeError::Io(std::io::Error::last_os_error()));
	}
	limit.rlim_cur = limit.rlim_max;
	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) } < 0 {
		return Err(OciRuntimeError::Io(std::io::Error::last_os_error()));
	}
	Ok(())
}

#[cfg(not(feature = "oci-devices"))]
fn apply_device_policy(_: &str) -> Result<(), OciRuntimeError> {
	Ok(())
}

#[cfg(feature = "oci-devices")]
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
	code: u8,
	registers: u8,
	offset: i16,
	immediate: i32,
}

#[cfg(feature = "oci-devices")]
impl BpfInsn {
	const fn new(
		code: u8,
		destination: u8,
		offset: i16,
		immediate: i32,
	) -> Self {
		Self { code, registers: destination, offset, immediate }
	}

	const fn load(destination: u8, offset: i16) -> Self {
		Self::new(0x61, 0x10 | destination, offset, 0)
	}
}

#[cfg(feature = "oci-devices")]
#[repr(C)]
#[derive(Default)]
struct BpfProgLoad {
	prog_type: u32,
	insn_cnt: u32,
	insns: u64,
	license: u64,
	log_level: u32,
	log_size: u32,
	log_buf: u64,
	kern_version: u32,
	prog_flags: u32,
	prog_name: [u8; 16],
	prog_ifindex: u32,
	expected_attach_type: u32,
}

#[cfg(feature = "oci-devices")]
#[repr(C)]
struct BpfProgAttach {
	target_fd: u32,
	attach_bpf_fd: u32,
	attach_type: u32,
	attach_flags: u32,
	replace_bpf_fd: u32,
}

#[cfg(feature = "oci-devices")]
fn device_program() -> Vec<BpfInsn> {
	let mut program = vec![
		BpfInsn::load(2, 0),
		BpfInsn::new(0x54, 2, 0, 0xffff),
		BpfInsn::load(4, 4),
		BpfInsn::load(5, 8),
	];
	for (major, minor) in [
		(1, Some(3)),
		(1, Some(5)),
		(1, Some(7)),
		(1, Some(8)),
		(1, Some(9)),
		(5, Some(0)),
		(5, Some(2)),
		(136, None),
	] {
		let comparisons = if minor.is_some() { 3 } else { 2 };
		program.push(BpfInsn::new(0x55, 2, comparisons + 1, 2));
		program.push(BpfInsn::new(0x55, 4, comparisons, major));
		if let Some(minor) = minor {
			program.push(BpfInsn::new(0x55, 5, 2, minor));
		}
		program
			.extend([BpfInsn::new(0xb7, 0, 0, 1), BpfInsn::new(0x95, 0, 0, 0)]);
	}
	program.extend([BpfInsn::new(0xb7, 0, 0, 0), BpfInsn::new(0x95, 0, 0, 0)]);
	program
}

fn device_rule(
	major: i64,
	minor: Option<i64>,
) -> Result<libcontainer::oci_spec::runtime::LinuxDeviceCgroup, OciRuntimeError>
{
	let mut builder = LinuxDeviceCgroupBuilder::default()
		.allow(true)
		.typ(LinuxDeviceType::C)
		.major(major)
		.access("rwm");
	if let Some(minor) = minor {
		builder = builder.minor(minor);
	}
	builder.build().map_err(config_error)
}

fn runtime_mounts(
	sandbox: &SandboxNamespaces,
	declared: &[ResolvedMount],
) -> Result<Vec<Mount>, OciRuntimeError> {
	let mut mounts = vec![
		mount("proc", "/proc", "proc", ["nosuid", "noexec", "nodev"]),
		mount(
			"tmpfs",
			"/dev",
			"tmpfs",
			["nosuid", "strictatime", "mode=755", "size=65536k"],
		),
		mount(
			"devpts",
			"/dev/pts",
			"devpts",
			[
				"nosuid",
				"noexec",
				"newinstance",
				"ptmxmode=0666",
				"mode=0620",
				"gid=5",
			],
		),
		bind_mount(&sandbox.shm, Path::new("/dev/shm"), false, false),
		mount("sysfs", "/sys", "sysfs", ["nosuid", "noexec", "nodev", "ro"]),
	];
	for declared in declared
		.iter()
		.filter(|mount| !mount.file)
		.chain(declared.iter().filter(|mount| mount.file))
	{
		mounts.push(bind_mount(
			&declared.source,
			&declared.destination,
			declared.read_only,
			!declared.file,
		));
	}
	mounts.into_iter().collect()
}

fn mount<const N: usize>(
	source: &str,
	destination: &str,
	typ: &str,
	options: [&str; N],
) -> Result<Mount, OciRuntimeError> {
	MountBuilder::default()
		.source(source)
		.destination(destination)
		.typ(typ)
		.options(options.map(str::to_owned).to_vec())
		.build()
		.map_err(config_error)
}

fn bind_mount(
	source: &Path,
	destination: &Path,
	read_only: bool,
	volume: bool,
) -> Result<Mount, OciRuntimeError> {
	let mut options = vec!["rbind".to_owned(), "nosuid".to_owned()];
	if volume {
		options.push("nodev".into());
	}
	if read_only {
		options.push("ro".into());
	}
	MountBuilder::default()
		.source(source)
		.destination(destination)
		.typ("bind")
		.options(options)
		.build()
		.map_err(config_error)
}

fn pipe() -> Result<(OwnedFd, OwnedFd), std::io::Error> {
	let (read, write) = UnixStream::pair()?;
	Ok((read.into(), write.into()))
}

fn drain_log(name: &str, stream: &str, fd: OwnedFd) -> thread::JoinHandle<()> {
	let name = name.to_owned();
	let stream = stream.to_owned();
	thread::spawn(move || {
		let mut reader = BufReader::new(File::from(fd));
		loop {
			let mut chunk = Vec::with_capacity(16 * 1024);
			match reader
				.by_ref()
				.take(MAX_LOG_CHUNK_BYTES)
				.read_until(b'\n', &mut chunk)
			{
				Ok(0) => break,
				Ok(_) => println!(
					"OCI[{name}][{stream}]: {}",
					String::from_utf8_lossy(&chunk)
						.trim_end_matches(['\r', '\n'])
				),
				Err(error) => {
					eprintln!("OCI[{name}][{stream}] log error: {error}");
					break;
				}
			}
		}
	})
}

#[allow(unsafe_code)]
fn wait_pid(pid: i32) -> Result<Termination, OciRuntimeError> {
	let mut status = 0;
	// SAFETY: status is a valid output pointer and pid is the recorded child.
	if unsafe { libc::waitpid(pid, &raw mut status, 0) } < 0 {
		return Err(OciRuntimeError::Io(std::io::Error::last_os_error()));
	}
	if libc::WIFEXITED(status) {
		Ok(Termination::ExitCode(libc::WEXITSTATUS(status)))
	} else if libc::WIFSIGNALED(status) {
		Ok(Termination::Signal(libc::WTERMSIG(status)))
	} else {
		Err(OciRuntimeError::Libcontainer(
			"unexpected container wait status".into(),
		))
	}
}

/// Signal a recorded parent-namespace PID. A process that already exited is
/// considered successfully stopped.
#[allow(unsafe_code)]
pub(crate) fn signal_pid(pid: i32, signal: i32) -> Result<(), OciRuntimeError> {
	// SAFETY: kill only reads scalar arguments. Callers use recorded child PIDs
	// and validated Linux signals.
	if unsafe { libc::kill(pid, signal) } == 0 {
		return Ok(());
	}
	let error = std::io::Error::last_os_error();
	if error.raw_os_error() == Some(libc::ESRCH) {
		Ok(())
	} else {
		Err(OciRuntimeError::Io(error))
	}
}

#[allow(unsafe_code)]
fn pid_alive(pid: i32) -> bool {
	// SAFETY: signal zero only checks whether the scalar PID exists.
	let exists = (unsafe { libc::kill(pid, 0) == 0 })
		|| std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
	if !exists {
		return false;
	}
	fs::read_to_string(format!("/proc/{pid}/stat"))
		.ok()
		.and_then(|stat| {
			stat.rsplit_once(") ").and_then(|(_, tail)| tail.chars().next())
		})
		.is_some_and(|state| !matches!(state, 'Z' | 'X'))
}

#[must_use]
pub(crate) fn sandbox_alive(pid: i32, namespaces: &SandboxNamespaces) -> bool {
	pid_alive(pid)
		&& [&namespaces.network, &namespaces.ipc, &namespaces.uts]
			.into_iter()
			.all(|path| path.exists())
}

fn runtime_error(error: impl std::fmt::Display) -> OciRuntimeError {
	OciRuntimeError::Libcontainer(error.to_string())
}

fn config_error(error: impl std::fmt::Display) -> OciRuntimeError {
	OciRuntimeError::Config(error.to_string())
}

pub(crate) fn record_error<T, E: std::fmt::Display>(
	errors: &mut Vec<String>,
	result: Result<T, E>,
) {
	if let Err(error) = result {
		errors.push(error.to_string());
	}
}

#[allow(unsafe_code)]
pub(crate) fn create_tmpfs(
	path: &Path,
	mode: u32,
	no_exec: bool,
) -> Result<(), OciRuntimeError> {
	fs::create_dir_all(path)?;
	let source =
		std::ffi::CString::new("qos-oci").expect("static string has no NUL");
	let target = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
		.map_err(|_| {
			OciRuntimeError::Config("tmpfs path contains NUL".into())
		})?;
	let typ =
		std::ffi::CString::new("tmpfs").expect("static string has no NUL");
	let data = std::ffi::CString::new(format!("mode={mode:o}"))
		.expect("formatted mode has no NUL");
	let mut flags = libc::MS_NODEV | libc::MS_NOSUID;
	if no_exec {
		flags |= libc::MS_NOEXEC;
	}
	// SAFETY: all C strings live through the syscall and flags/data are valid.
	if unsafe {
		libc::mount(
			source.as_ptr(),
			target.as_ptr(),
			typ.as_ptr(),
			flags,
			data.as_ptr().cast::<c_void>(),
		)
	} == 0
	{
		Ok(())
	} else {
		Err(OciRuntimeError::Io(std::io::Error::last_os_error()))
	}
}

#[allow(unsafe_code)]
pub(crate) fn unmount_path(path: &Path) -> Result<(), OciRuntimeError> {
	let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
		.map_err(|_| {
			OciRuntimeError::Config("mount path contains NUL".into())
		})?;
	// SAFETY: path is a valid C string. Lazy detach handles released namespace
	// references without blocking shutdown.
	if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } == 0 {
		Ok(())
	} else {
		let error = std::io::Error::last_os_error();
		if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)) {
			Ok(())
		} else {
			Err(OciRuntimeError::Io(error))
		}
	}
}

#[allow(unsafe_code)]
fn configure_loopback() -> Result<(), std::io::Error> {
	use libc::{
		AF_INET, IFF_UP, SIOCGIFFLAGS, SIOCSIFADDR, SIOCSIFFLAGS, SOCK_DGRAM,
		ifreq, sockaddr, sockaddr_in,
	};
	let fd = unsafe { libc::socket(AF_INET, SOCK_DGRAM, 0) };
	if fd < 0 {
		return Err(std::io::Error::last_os_error());
	}
	let mut request: ifreq = unsafe { std::mem::zeroed() };
	request.ifr_name[..3].copy_from_slice(&[
		b'l'.cast_signed(),
		b'o'.cast_signed(),
		0,
	]);
	let up = i16::try_from(IFF_UP).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid IFF_UP")
	})?;
	let family = u16::try_from(AF_INET).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid AF_INET")
	})?;
	let get_flags = IoctlRequest::try_from(SIOCGIFFLAGS).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid ioctl")
	})?;
	let set_flags = IoctlRequest::try_from(SIOCSIFFLAGS).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid ioctl")
	})?;
	let set_address = IoctlRequest::try_from(SIOCSIFADDR).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid ioctl")
	})?;
	let result = unsafe {
		if libc::ioctl(fd, get_flags, &mut request) < 0 {
			-1
		} else {
			request.ifr_ifru.ifru_flags |= up;
			if libc::ioctl(fd, set_flags, &request) < 0 {
				-1
			} else {
				let address = sockaddr_in {
					sin_family: family,
					sin_port: 0,
					sin_addr: libc::in_addr {
						s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
					},
					sin_zero: [0; 8],
				};
				std::ptr::copy_nonoverlapping(
					std::ptr::from_ref(&address).cast::<u8>(),
					std::ptr::addr_of_mut!(request.ifr_ifru.ifru_addr)
						.cast::<u8>(),
					size_of::<sockaddr>(),
				);
				libc::ioctl(fd, set_address, &request)
			}
		}
	};
	let error = std::io::Error::last_os_error();
	unsafe { libc::close(fd) };
	if result < 0 { Err(error) } else { Ok(()) }
}
