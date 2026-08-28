use qos_core::{
	handles::Handles,
	io::{SocketAddress, VMADDR_NO_FLAGS},
	reaper::Reaper,
	EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE,
};
use qos_nsm::Nsm;
use qos_system::{dmesg, freopen, get_local_cid, mount, reboot};

//TODO: Feature flag
use qos_aws::init_platform;

mod setip;
use setip::init_localhost;

const NODE_MAX_PROCESSES: &str = "4096";
const NODE_MAX_OPEN_FILES: &str = "65536";

#[allow(unsafe_code)]
fn configure_node_limits() -> std::io::Result<()> {
	std::fs::write("/proc/sys/kernel/pid_max", NODE_MAX_PROCESSES)?;
	std::fs::write("/proc/sys/kernel/threads-max", NODE_MAX_PROCESSES)?;
	std::fs::write("/proc/sys/fs/file-max", NODE_MAX_OPEN_FILES)?;
	let nofile = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
	let nproc = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
	// SAFETY: both pointers reference initialized rlimit values for the full
	// syscall. These fixed limits are inherited by every QOS child process.
	if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const nofile) } < 0
		|| unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &raw const nproc) } < 0
	{
		return Err(std::io::Error::last_os_error());
	}
	Ok(())
}

// Mount common filesystems with conservative permissions
fn init_rootfs() {
	use libc::{MS_NODEV, MS_NOEXEC, MS_NOSUID};
	let no_dse = MS_NODEV | MS_NOSUID | MS_NOEXEC;
	let no_ds = MS_NODEV | MS_NOSUID;
	let no_se = MS_NOSUID | MS_NOEXEC;
	let args = [
		("devtmpfs", "/dev", "devtmpfs", no_se, "mode=0755"),
		("devpts", "/dev/pts", "devpts", no_se, ""),
		("shm", "/dev/shm", "tmpfs", no_dse, "mode=0755"),
		("proc", "/proc", "proc", no_dse, "hidepid=2"),
		// OCI bundle root filesystems below /run must permit image executables.
		("tmpfs", "/run", "tmpfs", no_ds, "mode=0755"),
		("tmpfs", "/tmp", "tmpfs", no_dse, ""),
		("sysfs", "/sys", "sysfs", no_dse, ""),
		("cgroup2", "/sys/fs/cgroup", "cgroup2", no_dse, "nsdelegate"),
	];
	for (src, target, fstype, flags, data) in args {
		// Mounts above can hide initramfs children such as /dev/pts.
		if let Err(error) = std::fs::create_dir_all(target) {
			eprintln!("failed to create mount point {target}: {error}");
			continue;
		}
		match mount(src, target, fstype, flags, data) {
			Ok(()) => dmesg(format!("Mounted {target}")),
			Err(e) => eprintln!("{e}"),
		}
	}
}

// Initialize console with stdin/stdout/stderr
fn init_console() {
	let args = [
		("/dev/console", "r", 0),
		("/dev/console", "w", 1),
		("/dev/console", "w", 2),
	];
	for (filename, mode, file) in args {
		match freopen(filename, mode, file) {
			Ok(()) => {}
			Err(e) => eprintln!("{e}"),
		}
	}
}

fn boot() {
	init_rootfs();
	init_console();
	configure_node_limits().expect("failed to apply node-wide resource limits");
	init_platform();
	init_localhost();
	#[cfg(feature = "egress")]
	{
		dmesg("initializing egress tunnel interface".to_string());
		qos_core::egress::init_egress_tun();
	}
}

#[tokio::main]
async fn main() {
	if qos_core::oci_runtime::run_sandbox_if_requested() {
		return;
	}
	boot();
	dmesg("QuorumOS Booted".to_string());

	let cid = get_local_cid().unwrap();
	dmesg(format!("CID is {cid}"));

	let handles = Handles::new(
		EPHEMERAL_KEY_FILE.to_string(),
		QUORUM_FILE.to_string(),
		MANIFEST_FILE.to_string(),
		PIVOT_FILE.to_string(),
	);

	const START_PORT: u32 = 3;
	let core_socket =
		SocketAddress::new_vsock(cid, START_PORT, VMADDR_NO_FLAGS);

	Reaper::execute(&handles, Box::new(Nsm), core_socket, None).await;

	reboot();
}
