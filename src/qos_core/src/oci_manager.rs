//! Manifest V3 workload-group preparation, restart, and cleanup.

use std::{
	collections::BTreeMap,
	ffi::CString,
	fs::{self, File},
	os::fd::{AsRawFd, FromRawFd, OwnedFd},
	os::unix::ffi::OsStrExt,
	os::unix::fs::MetadataExt,
	panic::{AssertUnwindSafe, catch_unwind},
	path::{Component, Path, PathBuf},
	sync::{
		Arc, Mutex,
		atomic::{AtomicBool, Ordering},
	},
	thread,
	time::{Duration, Instant},
};

use crate::{
	handles::Handles,
	oci_bundle::{build_rootfs, prepare_directory_target, prepare_file_target},
	oci_image::{VerifiedOciImage, verify_oci_layout},
	oci_runtime::{
		OciRuntimeError, ResolvedMount, RuntimeContainer, RuntimeSandbox,
		SandboxNamespaces, create_tmpfs, record_error, sandbox_alive,
		signal_pid, unmount_path, write_config,
	},
	protocol::oci_status::{
		OciTermination, OciWorkloadStatus, SharedOciStatus,
	},
	protocol::services::boot::{
		ManifestV3, OciDigest, OciMount, OciName, OciRestartPolicy, VolumeV3,
		WorkloadV3,
	},
};

const RUNTIME_ROOT: &str = "/run/qos-oci";
const STABLE_RUN_TIME: Duration = Duration::from_secs(60);
const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const SUPERVISOR_INTERVAL: Duration = Duration::from_millis(20);

/// Workload-group preparation or lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum OciManagerError {
	/// Verified image or layer semantics were invalid.
	#[error("OCI image preparation failed: {0}")]
	Image(String),
	/// Parent or bundle filesystem operation failed.
	#[error("OCI manager filesystem operation failed: {0}")]
	Io(#[from] std::io::Error),
	/// Upstream container runtime operation failed.
	#[error(transparent)]
	Runtime(#[from] OciRuntimeError),
	/// A signed mount could not be resolved safely.
	#[error("invalid OCI mount: {0}")]
	Mount(String),
	/// A workload monitor thread failed.
	#[error("OCI workload monitor failed")]
	Monitor,
	/// A required namespace sandbox was lost.
	#[error("OCI workload sandbox was lost")]
	SandboxLost,
	/// One or more required cleanup operations failed.
	#[error("OCI cleanup failed: {0}")]
	Cleanup(String),
}

#[derive(Clone, Copy)]
struct RunningProcess {
	pid: i32,
	stop_signal: i32,
}

type RunningProcesses = Arc<Mutex<BTreeMap<OciName, RunningProcess>>>;

#[derive(Clone)]
struct Lifecycle {
	shutdown: Arc<AtomicBool>,
	running: RunningProcesses,
}

struct Volume {
	path: PathBuf,
}

impl Volume {
	fn create(path: &Path) -> Result<Self, OciManagerError> {
		prepare_parent_directory(path)?;
		if fs::symlink_metadata(path)?.uid() != 0 {
			return Err(OciManagerError::Mount(
				"tmpfs volume target is not owned by QOS root".into(),
			));
		}
		if fs::read_dir(path)?.next().is_some() {
			return Err(OciManagerError::Mount(
				"tmpfs volume target is not empty".into(),
			));
		}
		create_tmpfs(path, 0o1777, false)?;
		Ok(Self { path: path.to_owned() })
	}

	fn delete(self) -> Result<(), OciManagerError> {
		unmount_path(&self.path)?;
		fs::remove_dir(&self.path)?;
		Ok(())
	}
}

#[derive(Clone)]
struct PreparedWorkload {
	name: OciName,
	digest: OciDigest,
	restart: OciRestartPolicy,
	mounts: Vec<OciMount>,
	image: Arc<VerifiedOciImage>,
	volumes: Arc<BTreeMap<OciName, PathBuf>>,
	runtime_root: PathBuf,
	sandbox: SandboxNamespaces,
	status: SharedOciStatus,
	lifecycle: Lifecycle,
}

struct WorkloadRun {
	container: RuntimeContainer,
	bundle: PathBuf,
	pinned_files: Vec<File>,
	started: Instant,
	stop_signal: i32,
}

impl WorkloadRun {
	fn stop(mut self) -> Result<(), OciManagerError> {
		let mut errors = Vec::new();
		record_error(&mut errors, self.container.signal(libc::SIGKILL));
		record_error(&mut errors, self.container.wait());
		record_error(&mut errors, self.cleanup());
		cleanup_result(&errors)
	}

	fn cleanup(self) -> Result<(), OciManagerError> {
		let bundle = self.bundle.clone();
		let mut errors = Vec::new();
		record_error(&mut errors, self.container.delete());
		drop(self.pinned_files);
		if bundle.exists()
			&& let Err(error) = fs::remove_dir_all(bundle)
		{
			errors.push(error.to_string());
		}
		cleanup_result(&errors)
	}
}

impl PreparedWorkload {
	fn update_status(&self, update: impl FnOnce(&mut OciWorkloadStatus)) {
		if let Some(status) = self.status.write().unwrap().get_mut(&self.name) {
			update(status);
		}
	}

	fn create_run(&self) -> Result<WorkloadRun, OciManagerError> {
		let bundle = self.runtime_root.join("bundles").join(self.name.as_str());
		let rootfs = bundle.join("rootfs");
		let state = self.runtime_root.join("state");
		let stale_state = state.join(self.name.as_str());
		if stale_state.exists() {
			fs::remove_dir_all(&stale_state)?;
		}
		if bundle.exists() {
			fs::remove_dir_all(&bundle)?;
		}
		let result = (|| {
			fs::create_dir_all(&bundle)?;
			let process = build_rootfs(&self.image, &rootfs)
				.map_err(|error| OciManagerError::Image(error.to_string()))?;
			let (mounts, pinned_files) = self.resolve_mounts(&rootfs)?;
			write_config(
				&bundle,
				&rootfs,
				&process,
				&self.sandbox,
				&mounts,
				&self.name,
			)?;
			let container =
				RuntimeContainer::create(&self.name, &bundle, &state)?;
			Ok(WorkloadRun {
				container,
				bundle: bundle.clone(),
				pinned_files,
				started: Instant::now(),
				stop_signal: process.stop_signal,
			})
		})();
		match result {
			Ok(run) => Ok(run),
			Err(cause) => {
				let mut errors = Vec::new();
				if bundle.exists()
					&& let Err(error) = fs::remove_dir_all(&bundle)
				{
					errors.push(error.to_string());
				}
				if stale_state.exists()
					&& let Err(error) = fs::remove_dir_all(&stale_state)
				{
					errors.push(error.to_string());
				}
				if errors.is_empty() {
					Err(cause)
				} else {
					Err(OciManagerError::Cleanup(format!(
						"{cause}; {}",
						errors.join("; ")
					)))
				}
			}
		}
	}

	fn resolve_mounts(
		&self,
		rootfs: &Path,
	) -> Result<(Vec<ResolvedMount>, Vec<File>), OciManagerError> {
		let mut resolved = Vec::with_capacity(self.mounts.len());
		let mut pinned = Vec::new();
		for mount in &self.mounts {
			match mount {
				OciMount::Volume { source, mount_path, read_only } => {
					let source = self.volumes.get(source).ok_or_else(|| {
						OciManagerError::Mount("undeclared volume".into())
					})?;
					let destination = PathBuf::from(mount_path.as_str());
					prepare_directory_target(rootfs, &destination).map_err(
						|error| OciManagerError::Mount(error.to_string()),
					)?;
					resolved.push(ResolvedMount {
						source: source.clone(),
						destination,
						file: false,
						read_only: *read_only,
					});
				}
				OciMount::File { source, mount_path, read_only } => {
					let file = pin_regular_file(
						Path::new(source.as_str()),
						!*read_only,
					)?;
					let destination = PathBuf::from(mount_path.as_str());
					prepare_file_target(rootfs, &destination).map_err(
						|error| OciManagerError::Mount(error.to_string()),
					)?;
					resolved.push(ResolvedMount {
						source: PathBuf::from(format!(
							"/proc/self/fd/{}",
							file.as_raw_fd()
						)),
						destination,
						file: true,
						read_only: *read_only,
					});
					pinned.push(file);
				}
			}
		}
		Ok((resolved, pinned))
	}
}

/// Run all required Manifest V3 workloads until every `never` workload has
/// terminated. `always` workloads continue until the node is stopped.
///
/// # Errors
///
/// Returns an error when preparation, runtime supervision, or cleanup fails.
///
/// # Panics
///
/// Panics only if the shared status or lifecycle locks were poisoned.
#[allow(clippy::too_many_lines)]
pub fn run_oci_workloads(
	handles: &Handles,
	manifest: &ManifestV3,
	status: &SharedOciStatus,
	shutdown: &Arc<AtomicBool>,
) -> Result<(), OciManagerError> {
	let runtime_root = PathBuf::from(RUNTIME_ROOT);
	if runtime_root.exists() {
		return Err(OciManagerError::Mount(
			"OCI runtime root already exists".into(),
		));
	}
	fs::create_dir_all(&runtime_root)?;
	let images = match load_images(handles, manifest) {
		Ok(images) => images,
		Err(error) => {
			for entry in status.write().unwrap().values_mut() {
				entry.failed(&error, true);
			}
			return cleanup_without_sandbox(error, Vec::new(), &runtime_root);
		}
	};
	for entry in status.write().unwrap().values_mut() {
		entry.verified();
	}
	let (volumes, volume_paths) = match create_volumes(manifest) {
		Ok(volumes) => volumes,
		Err(error) => {
			return cleanup_without_sandbox(error, Vec::new(), &runtime_root);
		}
	};
	let sandbox = match RuntimeSandbox::create(&runtime_root) {
		Ok(sandbox) => sandbox,
		Err(error) => {
			return cleanup_without_sandbox(
				error.into(),
				volumes,
				&runtime_root,
			);
		}
	};
	let volume_paths = Arc::new(volume_paths);
	let lifecycle = Lifecycle {
		shutdown: Arc::clone(shutdown),
		running: Arc::new(Mutex::new(BTreeMap::new())),
	};
	let mut runs = Vec::with_capacity(manifest.workloads.len());
	let startup = (|| {
		for workload in &manifest.workloads {
			let sandbox_alive = sandbox.is_alive();
			if shutdown.load(Ordering::Acquire) || !sandbox_alive {
				let error = if sandbox_alive {
					OciManagerError::Cleanup(
						"shutdown requested during startup".into(),
					)
				} else {
					OciManagerError::SandboxLost
				};
				return Err((error, Vec::new()));
			}
			let prepared = prepare_workload(
				workload,
				&images,
				&volume_paths,
				&runtime_root,
				&sandbox.namespaces,
				status,
				&lifecycle,
			)
			.map_err(|error| (error, Vec::new()))?;
			let mut run =
				prepared.create_run().map_err(|error| (error, Vec::new()))?;
			let pid = match run.container.start() {
				Ok(pid) => pid,
				Err(error) => {
					prepared
						.update_status(|status| status.failed(&error, false));
					let cleanup = run
						.cleanup()
						.err()
						.map_or_else(Vec::new, |error| vec![error.to_string()]);
					return Err((error.into(), cleanup));
				}
			};
			register_process(&prepared, pid, run.stop_signal);
			prepared.update_status(|status| status.running(pid));
			println!(
				"OCI[{}] running verified image {}",
				prepared.name.as_str(),
				prepared.digest.as_str()
			);
			runs.push((prepared, run));
		}
		Ok::<(), (OciManagerError, Vec<String>)>(())
	})();
	if let Err((error, cleanup)) = startup {
		return cleanup_start_failure(
			error,
			cleanup,
			runs,
			sandbox,
			volumes,
			&runtime_root,
		);
	}
	println!("all OCI workloads started");
	let done = Arc::new(AtomicBool::new(false));
	let (sandbox_pid, sandbox_namespaces) = sandbox.health_handle();
	let supervisor = {
		let shutdown = Arc::clone(shutdown);
		let running = Arc::clone(&lifecycle.running);
		let done = Arc::clone(&done);
		thread::spawn(move || {
			supervise(
				&shutdown,
				&done,
				&running,
				sandbox_pid,
				&sandbox_namespaces,
			)
		})
	};
	let monitors: Vec<_> = runs
		.into_iter()
		.map(|(prepared, run)| {
			let shutdown = Arc::clone(shutdown);
			thread::spawn(move || {
				let result =
					catch_unwind(AssertUnwindSafe(|| monitor(&prepared, run)))
						.unwrap_or(Err(OciManagerError::Monitor));
				if result.is_err() {
					shutdown.store(true, Ordering::Release);
				}
				result
			})
		})
		.collect();
	let mut errors = Vec::new();
	for monitor in monitors {
		match monitor.join() {
			Ok(Ok(())) => {}
			Ok(Err(error)) => errors.push(error.to_string()),
			Err(_) => errors.push(OciManagerError::Monitor.to_string()),
		}
	}
	done.store(true, Ordering::Release);
	match supervisor.join() {
		Ok(Ok(())) => {}
		Ok(Err(error)) => errors.push(error.to_string()),
		Err(_) => errors.push(OciManagerError::Monitor.to_string()),
	}
	record_error(&mut errors, sandbox.delete());
	errors.extend(collect_cleanup_errors(volumes, Volume::delete));
	record_error(&mut errors, remove_runtime_root(&runtime_root));
	cleanup_result(&errors)
}

fn monitor(
	prepared: &PreparedWorkload,
	mut run: WorkloadRun,
) -> Result<(), OciManagerError> {
	let mut restart_count = 0_u64;
	let mut backoff = INITIAL_BACKOFF;
	loop {
		let termination = run.container.wait()?;
		unregister_process(prepared, None);
		let stable = run.started.elapsed() >= STABLE_RUN_TIME;
		println!("OCI[{}] terminated: {termination:?}", prepared.name.as_str());
		run.cleanup()?;
		if prepared.restart == OciRestartPolicy::Never
			|| prepared.lifecycle.shutdown.load(Ordering::Acquire)
		{
			prepared.update_status(|status| {
				status.terminated(status_termination(termination));
			});
			return Ok(());
		}
		if stable {
			backoff = INITIAL_BACKOFF;
		}
		prepared.update_status(|status| {
			status.restarting(restart_count, backoff);
		});
		if sleep_interruptible(backoff, &prepared.lifecycle.shutdown) {
			return Ok(());
		}
		loop {
			if prepared.lifecycle.shutdown.load(Ordering::Acquire) {
				return Ok(());
			}
			restart_count += 1;
			match prepared.create_run() {
				Ok(mut next) => match next.container.start() {
					Ok(pid) => {
						register_process(prepared, pid, next.stop_signal);
						prepared.update_status(|status| status.running(pid));
						println!(
							"OCI[{}] restarted ({restart_count})",
							prepared.name.as_str()
						);
						run = next;
						backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
						break;
					}
					Err(error) => {
						prepared.update_status(|status| {
							status.failed(&error, false);
						});
						eprintln!(
							"OCI[{}] restart failed: {error}",
							prepared.name.as_str()
						);
						next.cleanup()?;
					}
				},
				Err(error) => {
					prepared.update_status(|status| {
						status.failed(&error, false);
					});
					eprintln!(
						"OCI[{}] restart preparation failed: {error}",
						prepared.name.as_str()
					);
				}
			}
			backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
			prepared.update_status(|status| {
				status.restarting(restart_count, backoff);
			});
			if sleep_interruptible(backoff, &prepared.lifecycle.shutdown) {
				return Ok(());
			}
		}
	}
}

fn load_images(
	handles: &Handles,
	manifest: &ManifestV3,
) -> Result<BTreeMap<OciDigest, Arc<VerifiedOciImage>>, OciManagerError> {
	let mut images = BTreeMap::new();
	for workload in &manifest.workloads {
		let digest = workload.image().digest();
		if images.contains_key(digest) {
			continue;
		}
		let archive = handles.get_oci_archive(digest).map_err(|error| {
			OciManagerError::Image(format!("{}: {error}", digest.as_str()))
		})?;
		let image = verify_oci_layout(digest, &archive).map_err(|error| {
			OciManagerError::Image(format!("{}: {error}", digest.as_str()))
		})?;
		images.insert(digest.clone(), Arc::new(image));
	}
	Ok(images)
}

fn create_volumes(
	manifest: &ManifestV3,
) -> Result<(Vec<Volume>, BTreeMap<OciName, PathBuf>), OciManagerError> {
	let mut volumes = Vec::new();
	let mut paths = BTreeMap::new();
	for (name, volume) in &manifest.volumes {
		let VolumeV3::Tmpfs { mount_path } = volume;
		let path = PathBuf::from(mount_path.as_str());
		match Volume::create(&path) {
			Ok(volume) => {
				paths.insert(name.clone(), path);
				volumes.push(volume);
			}
			Err(error) => {
				let cleanup = cleanup_volumes(volumes);
				return if cleanup.is_empty() {
					Err(error)
				} else {
					Err(OciManagerError::Cleanup(format!(
						"{error}; {}",
						cleanup.join("; ")
					)))
				};
			}
		}
	}
	Ok((volumes, paths))
}

fn prepare_workload(
	workload: &WorkloadV3,
	images: &BTreeMap<OciDigest, Arc<VerifiedOciImage>>,
	volumes: &Arc<BTreeMap<OciName, PathBuf>>,
	runtime_root: &Path,
	sandbox: &SandboxNamespaces,
	status: &SharedOciStatus,
	lifecycle: &Lifecycle,
) -> Result<PreparedWorkload, OciManagerError> {
	let WorkloadV3::Oci { name, image, restart, mounts } = workload;
	let digest = image.digest().clone();
	Ok(PreparedWorkload {
		name: name.clone(),
		digest: digest.clone(),
		restart: *restart,
		mounts: mounts.clone(),
		image: images.get(&digest).cloned().ok_or_else(|| {
			OciManagerError::Image("missing verified image".into())
		})?,
		volumes: Arc::clone(volumes),
		runtime_root: runtime_root.to_owned(),
		sandbox: sandbox.clone(),
		status: Arc::clone(status),
		lifecycle: lifecycle.clone(),
	})
}

fn status_termination(
	termination: crate::oci_runtime::Termination,
) -> OciTermination {
	match termination {
		crate::oci_runtime::Termination::ExitCode(code) => {
			OciTermination::ExitCode(code)
		}
		crate::oci_runtime::Termination::Signal(signal) => {
			OciTermination::Signal(signal)
		}
	}
}

fn register_process(prepared: &PreparedWorkload, pid: i32, stop_signal: i32) {
	prepared
		.lifecycle
		.running
		.lock()
		.unwrap()
		.insert(prepared.name.clone(), RunningProcess { pid, stop_signal });
}

fn unregister_process(prepared: &PreparedWorkload, pid: Option<i32>) {
	let mut running = prepared.lifecycle.running.lock().unwrap();
	if pid.is_none_or(|pid| {
		running.get(&prepared.name).is_some_and(|process| process.pid == pid)
	}) {
		running.remove(&prepared.name);
	}
}

fn supervise(
	shutdown: &AtomicBool,
	done: &AtomicBool,
	running: &RunningProcesses,
	sandbox_pid: i32,
	sandbox: &SandboxNamespaces,
) -> Result<(), OciManagerError> {
	let mut sandbox_lost = false;
	while !done.load(Ordering::Acquire) && !shutdown.load(Ordering::Acquire) {
		if !sandbox_alive(sandbox_pid, sandbox) {
			sandbox_lost = true;
			shutdown.store(true, Ordering::Release);
			break;
		}
		thread::sleep(SUPERVISOR_INTERVAL);
	}
	if shutdown.load(Ordering::Acquire) {
		stop_registered_processes(running)?;
	}
	if sandbox_lost { Err(OciManagerError::SandboxLost) } else { Ok(()) }
}

fn stop_registered_processes(
	running: &RunningProcesses,
) -> Result<(), OciManagerError> {
	let initial = running.lock().unwrap().clone();
	let mut errors = Vec::new();
	for process in initial.values() {
		record_error(&mut errors, signal_pid(process.pid, process.stop_signal));
	}
	let deadline = Instant::now() + STOP_TIMEOUT;
	while Instant::now() < deadline {
		if running.lock().unwrap().is_empty() {
			return cleanup_result(&errors);
		}
		thread::sleep(SUPERVISOR_INTERVAL);
	}
	let remaining = running.lock().unwrap().clone();
	for (name, process) in remaining {
		if initial.get(&name).is_some_and(|started| started.pid == process.pid)
			&& let Err(error) = signal_pid(process.pid, libc::SIGKILL)
		{
			errors.push(error.to_string());
		}
	}
	cleanup_result(&errors)
}

fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) -> bool {
	let deadline = Instant::now() + duration;
	while Instant::now() < deadline {
		if shutdown.load(Ordering::Acquire) {
			return true;
		}
		let remaining = deadline.saturating_duration_since(Instant::now());
		if remaining.is_zero() {
			break;
		}
		thread::sleep(SUPERVISOR_INTERVAL.min(remaining));
	}
	shutdown.load(Ordering::Acquire)
}

fn collect_cleanup_errors<T>(
	items: impl IntoIterator<Item = T>,
	mut cleanup: impl FnMut(T) -> Result<(), OciManagerError>,
) -> Vec<String> {
	let mut errors = Vec::new();
	for item in items {
		if let Err(error) = cleanup(item) {
			errors.push(error.to_string());
		}
	}
	errors
}

fn cleanup_volumes(volumes: Vec<Volume>) -> Vec<String> {
	collect_cleanup_errors(volumes.into_iter().rev(), Volume::delete)
}

fn cleanup_start_failure(
	cause: OciManagerError,
	mut errors: Vec<String>,
	runs: Vec<(PreparedWorkload, WorkloadRun)>,
	sandbox: RuntimeSandbox,
	volumes: Vec<Volume>,
	runtime_root: &Path,
) -> Result<(), OciManagerError> {
	errors.extend(collect_cleanup_errors(runs, |(_, run)| run.stop()));
	record_error(&mut errors, sandbox.delete());
	errors.extend(cleanup_volumes(volumes));
	record_error(&mut errors, remove_runtime_root(runtime_root));
	cleanup_cause(cause, &errors)
}

fn cleanup_without_sandbox(
	cause: OciManagerError,
	volumes: Vec<Volume>,
	runtime_root: &Path,
) -> Result<(), OciManagerError> {
	let mut errors = cleanup_volumes(volumes);
	record_error(&mut errors, remove_runtime_root(runtime_root));
	cleanup_cause(cause, &errors)
}

fn cleanup_cause(
	cause: OciManagerError,
	errors: &[String],
) -> Result<(), OciManagerError> {
	if errors.is_empty() {
		Err(cause)
	} else {
		Err(OciManagerError::Cleanup(format!("{cause}; {}", errors.join("; "))))
	}
}

fn remove_runtime_root(path: &Path) -> Result<(), OciManagerError> {
	if path.exists() {
		fs::remove_dir_all(path)?;
	}
	Ok(())
}

fn cleanup_result(errors: &[String]) -> Result<(), OciManagerError> {
	if errors.is_empty() {
		Ok(())
	} else {
		Err(OciManagerError::Cleanup(errors.join("; ")))
	}
}

fn prepare_parent_directory(path: &Path) -> Result<(), OciManagerError> {
	if !path.is_absolute() || path == Path::new("/") {
		return Err(OciManagerError::Mount(
			"volume path is not absolute and non-root".into(),
		));
	}
	let mut current = PathBuf::from("/");
	for component in path.components().skip(1) {
		let Component::Normal(part) = component else {
			return Err(OciManagerError::Mount(
				"volume path is not normalized".into(),
			));
		};
		current.push(part);
		match fs::symlink_metadata(&current) {
			Ok(metadata) if metadata.is_dir() => {}
			Ok(_) => {
				return Err(OciManagerError::Mount(
					"volume parent is not a directory".into(),
				));
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				fs::create_dir(&current)?;
			}
			Err(error) => return Err(error.into()),
		}
	}
	Ok(())
}

#[allow(unsafe_code)]
fn pin_regular_file(
	path: &Path,
	writable: bool,
) -> Result<File, OciManagerError> {
	if !path.is_absolute()
		|| path.components().any(|component| {
			matches!(component, Component::CurDir | Component::ParentDir)
		}) {
		return Err(OciManagerError::Mount(
			"file source is not a normalized absolute path".into(),
		));
	}
	let mut directory = File::open("/")?;
	let parts: Vec<_> = path
		.components()
		.filter_map(|component| match component {
			Component::Normal(part) => Some(part),
			_ => None,
		})
		.collect();
	if parts.is_empty() {
		return Err(OciManagerError::Mount("file source is root".into()));
	}
	for (index, part) in parts.iter().enumerate() {
		let part = CString::new(part.as_bytes()).map_err(|_| {
			OciManagerError::Mount("file source contains NUL".into())
		})?;
		let last = index + 1 == parts.len();
		let flags = if last {
			(if writable { libc::O_RDWR } else { libc::O_RDONLY })
				| libc::O_NOFOLLOW
				| libc::O_CLOEXEC
		} else {
			libc::O_PATH
				| libc::O_DIRECTORY
				| libc::O_NOFOLLOW
				| libc::O_CLOEXEC
		};
		// SAFETY: directory and part remain valid through openat; ownership of a
		// successful descriptor transfers immediately to OwnedFd.
		let fd = unsafe {
			libc::openat(directory.as_raw_fd(), part.as_ptr(), flags)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		let owned = unsafe { OwnedFd::from_raw_fd(fd) };
		directory = File::from(owned);
	}
	if !directory.metadata()?.is_file() {
		return Err(OciManagerError::Mount(
			"file source is not a regular file".into(),
		));
	}
	Ok(directory)
}
