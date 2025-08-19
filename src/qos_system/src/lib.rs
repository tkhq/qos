use std::{
	ffi::CString,
	fmt,
	fs::File,
	mem::{size_of, zeroed},
	os::unix::io::AsRawFd,
};

use libc::{c_int, c_ulong, c_void};

#[derive(Debug)]
pub struct SystemError {
	pub message: String,
}
impl fmt::Display for SystemError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{} {}", boot_time(), self.message)
	}
}

/// Log dmesg formatted log to console
pub fn dmesg(message: String) {
	println!("{} {}", boot_time(), message);
}

/// Dmesg formatted seconds since boot
pub fn boot_time() -> String {
	use libc::{clock_gettime, timespec, CLOCK_BOOTTIME};
	let mut t = timespec { tv_sec: 0, tv_nsec: 0 };
	unsafe {
		clock_gettime(CLOCK_BOOTTIME, &mut t as *mut timespec);
	}
	format!("[ {: >4}.{}]", t.tv_sec, t.tv_nsec / 1000).to_string()
}

/// Unconditionally reboot the system now
pub fn reboot() {
	use libc::{reboot, RB_AUTOBOOT};
	unsafe {
		reboot(RB_AUTOBOOT);
	}
}

/// Unconditionally halt the system now
pub fn poweroff() {
	use libc::{reboot, RB_POWER_OFF};
	unsafe {
		reboot(RB_POWER_OFF);
	}
}

/// libc::mount casting/error wrapper
pub fn mount(
	src: &str,
	target: &str,
	fstype: &str,
	flags: c_ulong,
	data: &str,
) -> Result<(), SystemError> {
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
		Err(SystemError { message: format!("Failed to mount: {}", target) })
	} else {
		Ok(())
	}
}

/// libc::freopen casting/error wrapper
pub fn freopen(
	filename: &str,
	mode: &str,
	file: c_int,
) -> Result<(), SystemError> {
	use libc::{fdopen, freopen};
	let filename_cs = CString::new(filename).unwrap();
	let mode_cs = CString::new(mode).unwrap();
	if unsafe {
		freopen(
			filename_cs.as_ptr(),
			mode_cs.as_ptr(),
			// TODO clippy says the pointer casting is unecessary
			// is this true for all configurations and platforms?
			fdopen(file, mode_cs.as_ptr() as *const i8),
		)
	}
	.is_null()
	{
		Err(SystemError { message: format!("Failed to freopen: {}", filename) })
	} else {
		Ok(())
	}
}

/// Insert kernel module into memory
pub fn insmod(path: &str) -> Result<(), SystemError> {
	use libc::{syscall, SYS_finit_module};
	let file = File::open(path).unwrap();
	let fd = file.as_raw_fd();
	if unsafe { syscall(SYS_finit_module, fd, &[0u8; 1], 0) } < 0 {
		Err(SystemError {
			message: format!("Failed to insert kernel module: {}", path),
		})
	} else {
		Ok(())
	}
}

/// Instantiate a socket
pub fn socket_connect(
	family: c_int,
	port: u32,
	cid: u32,
) -> Result<c_int, SystemError> {
	use libc::{connect, sockaddr, sockaddr_vm, socket, SOCK_STREAM};
	let fd = unsafe { socket(family, SOCK_STREAM, 0) };
	if unsafe {
		let mut sa: sockaddr_vm = zeroed();
		sa.svm_family = family as _;
		sa.svm_port = port;
		sa.svm_cid = cid;
		connect(
			fd,
			&sa as *const _ as *mut sockaddr,
			size_of::<sockaddr_vm>() as _,
		)
	} < 0
	{
		Err(SystemError {
			message: format!("Failed to connect to socket: {}", family),
		})
	} else {
		Ok(fd)
	}
}

/// Verify expected hwrng is loaded
pub fn check_hwrng(rng_expected: &str) -> Result<(), SystemError> {
	use std::fs::read_to_string;
	let filename: &str = "/sys/class/misc/hw_random/rng_current";
	let rng_current_raw = read_to_string(filename)
		.map_err(|_| SystemError {
			message: format!("Failed to read {}", &filename),
		})?;
	let rng_current = rng_current_raw.trim();
	if rng_expected != rng_current {
		return Err(SystemError {
			message: format!(
				"Entropy source was {} instead of {}",
				rng_current, rng_expected
			),
		})
	};
	Ok(())
}

#[cfg(target_env = "musl")]
type IoctlNumType = ::libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlNumType = ::libc::c_ulong;

const IOCTL_VM_SOCKETS_GET_LOCAL_CID: IoctlNumType = 0x7b9;

pub fn get_local_cid() -> Result<u32, SystemError> {
	use libc::ioctl;
	let f = match File::open("/dev/vsock") {
		Ok(f) => f,
		Err(_e) => return Err(SystemError{ message: "Failed to open /dev/vsock".to_string() }),
	};
	let mut cid = 0;
	if unsafe { ioctl(f.as_raw_fd(), IOCTL_VM_SOCKETS_GET_LOCAL_CID, &mut cid) } == -1 {
		return Err(SystemError{ message: "Failed to fetch local CID".to_string() });
	}
	Ok(cid)
}
