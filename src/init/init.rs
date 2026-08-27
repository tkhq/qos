#[cfg(not(feature = "qemu-stagex-e2e"))]
use qos_core::{
	EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE,
	handles::Handles,
	io::{SocketAddress, VMADDR_NO_FLAGS},
	reaper::Reaper,
};
#[cfg(not(feature = "qemu-stagex-e2e"))]
use qos_nsm::Nsm;
use qos_system::{dmesg, freopen, mount};
#[cfg(not(feature = "qemu-stagex-e2e"))]
use qos_system::{get_local_cid, reboot};

#[cfg(feature = "qemu-stagex-e2e")]
mod qemu_stagex_e2e;

#[cfg(not(feature = "qemu-stagex-e2e"))]
use qos_aws::init_platform;

mod setip;
use setip::init_localhost;

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
		// OCI bundles and their executable rootfs live below /run/qos/oci.
		("tmpfs", "/run", "tmpfs", no_ds, "mode=0755"),
		("tmpfs", "/tmp", "tmpfs", no_dse, ""),
		("sysfs", "/sys", "sysfs", no_dse, ""),
		("cgroup2", "/sys/fs/cgroup", "cgroup2", no_dse, "nsdelegate"),
	];
	for (src, target, fstype, flags, data) in args {
		// Earlier mounts can hide the initramfs directories beneath them. In
		// particular, mounting devtmpfs on /dev hides /dev/pts and /dev/shm.
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
	#[cfg(not(feature = "qemu-stagex-e2e"))]
	init_platform();
	init_localhost();
}

#[tokio::main]
async fn main() {
	boot();
	dmesg("QuorumOS Booted".to_string());

	#[cfg(feature = "qemu-stagex-e2e")]
	qemu_stagex_main();

	#[cfg(not(feature = "qemu-stagex-e2e"))]
	production_main().await;
}

#[cfg(feature = "qemu-stagex-e2e")]
fn qemu_stagex_main() {
	if let Err(error) = qemu_stagex_e2e::run() {
		eprintln!("QOS_STAGEX_BUILDKIT_E2E_FAILED: {error}");
	}
	qos_system::poweroff();
}

#[cfg(not(feature = "qemu-stagex-e2e"))]
async fn production_main() {
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
