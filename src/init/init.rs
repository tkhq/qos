extern crate libc;
use std::{
	ffi::CString,
	fs::File,
	mem::{size_of, zeroed},
	os::unix::io::AsRawFd,
};

use libc::{c_int, c_ulong, c_void, MS_NODEV, MS_NOEXEC, MS_NOSUID};

// Log errors to console
pub fn error(message: String) {
	eprintln!("{} {}", boot_time(), message);
}

// Log info to console
pub fn info(message: String) {
	println!("{} {}", boot_time(), message);
}

pub fn reboot() {
	use libc::{reboot, RB_AUTOBOOT};
	unsafe {
		reboot(RB_AUTOBOOT);
	}
}

// Dmesg formatted seconds since boot
pub fn boot_time() -> String {
	use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
	let mut t = timespec { tv_sec: 0, tv_nsec: 0 };
	unsafe {
		clock_gettime(CLOCK_BOOTTIME, &mut t as *mut timespec);
	}
	format!("[ {: >4}.{}]", t.tv_sec, t.tv_nsec / 1000).to_string()
}

// libc::mount casting/error wrapper
pub fn mount(
	src: &str,
	target: &str,
	fstype: &str,
	flags: c_ulong,
	data: &str,
) {
	use libc::mount;
	let src_cs = CString::new(src).unwrap();
	let fstype_cs = CString::new(fstype).unwrap();
	let data_cs = CString::new(data).unwrap();
	let target_cs = CString::new(target).unwrap();
	if unsafe {
		mount(
			src_cs.as_ptr(),
			target_cs.as_ptr(),
			fstype_cs.as_ptr(),
			flags,
			data_cs.as_ptr() as *const c_void,
		)
	} != 0
	{
		error(format!("Failed to mount: {}", target));
	} else {
		info(format!("Mounted: {}", target));
	}
}

// libc::freopen casting/error wrapper
pub fn freopen(filename: &str, mode: &str, file: c_int) {
	use libc::{fdopen, freopen};
	let filename_cs = CString::new(filename).unwrap();
	let mode_cs = CString::new(mode).unwrap();
	if unsafe {
		freopen(
			filename_cs.as_ptr(),
			mode_cs.as_ptr(),
			fdopen(file, mode_cs.as_ptr() as *const i8),
		)
	}
	.is_null()
	{
		error(format!("Failed to freopen: {}", filename));
	}
}

// Insert kernel module into memory
pub fn insmod(path: &str) {
	use libc::{syscall, SYS_finit_module};
	let file = File::open(path).unwrap();
	let fd = file.as_raw_fd();
	if unsafe { syscall(SYS_finit_module, fd, &[0u8; 1], 0) } < 0 {
		error(format!("Failed to insert kernel module: {}", path));
	} else {
		info(format!("Loaded kernel module: {}", path));
	}
}

// Signal to Nitro hypervisor that booting was successful
pub fn nitro_heartbeat() {
	use libc::{
		close, connect, read, sockaddr, sockaddr_vm, socket, write, AF_VSOCK,
		SOCK_STREAM,
	};
	let mut buf: [u8; 1] = [0; 1];
	buf[0] = 0xB7; // AWS Nitro heartbeat value
	unsafe {
		let mut sa: sockaddr_vm = zeroed();
		sa.svm_family = AF_VSOCK as _;
		sa.svm_port = 9000;
		sa.svm_cid = 3;
		let fd = socket(AF_VSOCK, SOCK_STREAM, 0);
		connect(
			fd,
			&sa as *const _ as *mut sockaddr,
			size_of::<sockaddr_vm>() as _,
		);
		write(fd, buf.as_ptr() as _, 1);
		read(fd, buf.as_ptr() as _, 1);
		close(fd);
	}
	info(format!("Sent NSM heartbeat"));
}

// Get entropy sample from Nitro device
pub fn nitro_get_entropy() -> [u8; 256] {
	use nsm_api::api::ErrorCode;
	use nsm_lib::{nsm_get_random, nsm_lib_init};

	let nsm_fd = nsm_lib_init();
	if nsm_fd < 0 {
		error(format!("Failed to connect to NSM device"));
	};

	let mut dest: [u8; 256] = [0; 256];
	let mut dest_len = dest.len();

	let status =
		unsafe { nsm_get_random(nsm_fd, dest.as_mut_ptr(), &mut dest_len) };
	match status {
		ErrorCode::Success => {
            info(format!("Entropy seeding success"));
            dest
        },
		_ => {
            error(format!("Failed to get entropy from NSM device"));
            panic!("Failed to get entropy from NSM device");
        }
	}
}

pub fn init_nitro() {
	nitro_heartbeat();
	insmod("/nsm.ko");
	nitro_get_entropy();
}

// Initialize console with stdin/stdout/stderr
pub fn init_console() {
	freopen("/dev/console", "r", 0);
	freopen("/dev/console", "w", 1);
	freopen("/dev/console", "w", 2);
	info(format!("Initialized console"));
}

// Mount common filesystems with conservative permissions
pub fn init_rootfs() {
	mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
	mount(
		"proc",
		"/proc",
		"proc",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"hidepid=2",
	);
	mount(
		"tmpfs",
		"/run",
		"tmpfs",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"mode=0755",
	);
	mount("tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "");
	mount(
		"shm",
		"/dev/shm",
		"tmpfs",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"mode=0755",
	);
	mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "");
	mount("sysfs", "/sys", "sysfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "");
	mount(
		"cgroup_root",
		"/sys/fs/cgroup",
		"tmpfs",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"mode=0755",
	);
}

pub fn boot() {
	init_rootfs();
	init_console();
    // This can panic
	init_nitro();
}

fn main() {
	boot();
	info("EnclaveOS Booted".to_string());
	reboot();
}
