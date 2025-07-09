use qos_core::{
	handles::Handles,
	io::{SocketAddress, VMADDR_NO_FLAGS},
	reaper::Reaper,
	EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE, SEC_APP_SOCK,
};
use qos_nsm::Nsm;
use qos_system::{dmesg, freopen, get_local_cid, mount, reboot};

//TODO: Feature flag
use qos_aws::init_platform;

// Mount common filesystems with conservative permissions
fn init_rootfs() {
	use libc::{MS_NODEV, MS_NOEXEC, MS_NOSUID};
	let no_dse = MS_NODEV | MS_NOSUID | MS_NOEXEC;
	let no_se = MS_NOSUID | MS_NOEXEC;
	let args = [
		("devtmpfs", "/dev", "devtmpfs", no_se, "mode=0755"),
		("devpts", "/dev/pts", "devpts", no_se, ""),
		("shm", "/dev/shm", "tmpfs", no_dse, "mode=0755"),
		("proc", "/proc", "proc", no_dse, "hidepid=2"),
		("tmpfs", "/run", "tmpfs", no_dse, "mode=0755"),
		("tmpfs", "/tmp", "tmpfs", no_dse, ""),
		("sysfs", "/sys", "sysfs", no_dse, ""),
		("cgroup_root", "/sys/fs/cgroup", "tmpfs", no_dse, "mode=0755"),
	];
	for (src, target, fstype, flags, data) in args {
		match mount(src, target, fstype, flags, data) {
			Ok(()) => dmesg(format!("Mounted {}", target)),
			Err(e) => eprintln!("{}", e),
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
			Err(e) => eprintln!("{}", e),
		}
	}
}

fn boot() {
	init_rootfs();
	init_console();
	init_platform();
}

#[cfg(not(feature = "async"))]
fn main() {
	boot();
	dmesg("QuorumOS Booted".to_string());

	let cid = get_local_cid().unwrap();
	dmesg(format!("CID is {}", cid));

	let handles = Handles::new(
		EPHEMERAL_KEY_FILE.to_string(),
		QUORUM_FILE.to_string(),
		MANIFEST_FILE.to_string(),
		PIVOT_FILE.to_string(),
	);

	Reaper::execute(
		&handles,
		Box::new(Nsm),
		SocketAddress::new_vsock(cid, 3, VMADDR_NO_FLAGS),
		SocketAddress::new_unix(SEC_APP_SOCK),
		None,
	);

	reboot();
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() {
	use qos_core::io::{AsyncStreamPool, TimeVal, TimeValLike};

	boot();
	dmesg("QuorumOS Booted in Async mode".to_string());

	let cid = get_local_cid().unwrap();
	dmesg(format!("CID is {}", cid));

	let handles = Handles::new(
		EPHEMERAL_KEY_FILE.to_string(),
		QUORUM_FILE.to_string(),
		MANIFEST_FILE.to_string(),
		PIVOT_FILE.to_string(),
	);

	let start_port = 3; // used for qos-host only! others follow 4+ for the <app>-host
	let core_pool = AsyncStreamPool::new(
		SocketAddress::new_vsock(cid, start_port, VMADDR_NO_FLAGS),
		TimeVal::seconds(0),
		1, // start at pool size 1, grow based on  manifest/args as necessary (see Reaper)
	)
	.expect("unable to create core pool");

	let app_pool = AsyncStreamPool::new(
		SocketAddress::new_unix(SEC_APP_SOCK),
		TimeVal::seconds(5),
		1, // start at pool size 1, grow based on  manifest/args as necessary (see Reaper)
	)
	.expect("unable to create app pool");

	Reaper::async_execute(&handles, Box::new(Nsm), core_pool, app_pool, None);

	reboot();
}
