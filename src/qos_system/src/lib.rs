use std::{
	ffi::CString,
	fmt,
	fs::File,
	io::Read,
	mem::{size_of, zeroed},
	os::unix::io::AsRawFd,
	path::Path,
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
	use libc::{CLOCK_BOOTTIME, clock_gettime, timespec};
	let mut t = timespec { tv_sec: 0, tv_nsec: 0 };
	unsafe {
		clock_gettime(CLOCK_BOOTTIME, &mut t as *mut timespec);
	}
	format!("[ {: >4}.{}]", t.tv_sec, t.tv_nsec / 1000).to_string()
}

/// Unconditionally reboot the system now
pub fn reboot() {
	use libc::{RB_AUTOBOOT, reboot};
	unsafe {
		reboot(RB_AUTOBOOT);
	}
}

/// Unconditionally halt the system now
pub fn poweroff() {
	use libc::{RB_POWER_OFF, reboot};
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
	let mount_result = unsafe {
		mount(
			src_cs.as_ptr(),
			target_cs.as_ptr(),
			fstype_cs.as_ptr(),
			flags,
			data_cs.as_ptr() as *const c_void,
		)
	};

	if mount_result != 0 {
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
	let freopen_result = unsafe {
		freopen(
			filename_cs.as_ptr(),
			mode_cs.as_ptr(),
			// TODO clippy says the pointer casting is unecessary
			// is this true for all configurations and platforms?
			fdopen(file, mode_cs.as_ptr() as *const i8),
		)
	};
	if freopen_result.is_null() {
		Err(SystemError { message: format!("Failed to freopen: {}", filename) })
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
	use libc::{SOCK_STREAM, connect, sockaddr, sockaddr_vm, socket};
	let fd = unsafe { socket(family, SOCK_STREAM, 0) };
	let connect_result = unsafe {
		let mut sa: sockaddr_vm = zeroed();
		sa.svm_family = family as _;
		sa.svm_port = port;
		sa.svm_cid = cid;
		connect(
			fd,
			&sa as *const _ as *mut sockaddr,
			size_of::<sockaddr_vm>() as _,
		)
	};

	if connect_result < 0 {
		Err(SystemError {
			message: format!("Failed to connect to socket: {}", family),
		})
	} else {
		Ok(fd)
	}
}

const HWRNG_SYSFS_DIR: &str = "/sys/class/misc/hw_random";
const HWRNG_DEV: &str = "/dev/hwrng";
// The hwrng core fetches from the device in chunks of at most 64 bytes on
// x86_64 (RNG_BUFFER_SIZE) and hands them out across reads. 64-byte samples
// make each sample a separate device fetch, so comparing them can catch a
// device that repeats itself.
const HWRNG_SAMPLE_LEN: usize = 64;

/// Output read from the hwrng by [`check_hwrng`].
pub type HwrngSample = [u8; 2 * HWRNG_SAMPLE_LEN];

/// Verify the kernel uses the expected hwrng, credits it with the expected
/// quality, and that it produces output that is not stuck. Returns the output
/// it read, for [`reseed_crng`].
pub fn check_hwrng(
	rng_expected: &str,
	quality_expected: u16,
) -> Result<HwrngSample, SystemError> {
	check_hwrng_at(
		Path::new(HWRNG_SYSFS_DIR),
		Path::new(HWRNG_DEV),
		rng_expected,
		quality_expected,
	)
}

fn check_hwrng_at(
	sysfs_dir: &Path,
	dev: &Path,
	rng_expected: &str,
	quality_expected: u16,
) -> Result<HwrngSample, SystemError> {
	let rng_current = read_sysfs(&sysfs_dir.join("rng_current"))?;
	if rng_current != rng_expected {
		return Err(SystemError {
			message: format!(
				"Entropy source was {rng_current} instead of {rng_expected}"
			),
		});
	}

	let quality = read_sysfs(&sysfs_dir.join("rng_quality"))?;
	if quality.parse::<u16>().ok() != Some(quality_expected) {
		return Err(SystemError {
			message: format!(
				"Entropy source quality was {quality} instead of {quality_expected}"
			),
		});
	}

	// Catches a device that errors or is stuck, not subtle bias. The kernel
	// mixes this source with others, so it is not the only defense.
	let read_err = |_: std::io::Error| SystemError {
		message: format!("Failed to read {}", dev.display()),
	};
	let mut hwrng = File::open(dev).map_err(read_err)?;
	let mut sample: HwrngSample = [0; 2 * HWRNG_SAMPLE_LEN];
	let (first, second) = sample.split_at_mut(HWRNG_SAMPLE_LEN);
	hwrng.read_exact(first).map_err(read_err)?;
	hwrng.read_exact(second).map_err(read_err)?;
	let constant = |s: &[u8]| s.iter().all(|b| *b == s[0]);
	if first == second || constant(first) || constant(second) {
		return Err(SystemError {
			message: format!("Entropy source {rng_current} output is stuck"),
		});
	}
	Ok(sample)
}

fn read_sysfs(path: &Path) -> Result<String, SystemError> {
	std::fs::read_to_string(path).map(|s| s.trim().to_string()).map_err(|_| {
		SystemError { message: format!("Failed to read {}", path.display()) }
	})
}

#[cfg(target_env = "musl")]
type IoctlNumType = ::libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlNumType = ::libc::c_ulong;

const IOCTL_VM_SOCKETS_GET_LOCAL_CID: IoctlNumType = 0x7b9;
// _IO('R', 0x07) from linux/random.h; libc doesn't define it.
const RNDRESEEDCRNG: IoctlNumType = 0x5207;

/// Mix `sample` into the kernel's entropy pool and reseed the CRNG, so its
/// output depends on `sample` from now on. Without this, the kernel can mark
/// the CRNG ready from the CPU RNG alone and only take in hwrng output at its
/// next scheduled reseed. Needs `CAP_SYS_ADMIN`.
pub fn reseed_crng(sample: &[u8]) -> Result<(), SystemError> {
	use std::{fs::OpenOptions, io::Write};
	let err = |message: &str| SystemError { message: message.to_string() };

	// RNDRESEEDCRNG fails until the CRNG is ready; getrandom blocks until then.
	let mut byte = [0u8; 1];
	if unsafe { libc::getrandom(byte.as_mut_ptr().cast(), 1, 0) } != 1 {
		return Err(err("Failed to wait for the CRNG to be ready"));
	}

	// A write mixes the bytes into the pool without crediting entropy.
	let mut random = OpenOptions::new()
		.write(true)
		.open("/dev/random")
		.map_err(|_| err("Failed to open /dev/random"))?;
	random
		.write_all(sample)
		.map_err(|_| err("Failed to write to /dev/random"))?;

	if unsafe { libc::ioctl(random.as_raw_fd(), RNDRESEEDCRNG) } != 0 {
		return Err(err("Failed to reseed the CRNG"));
	}
	Ok(())
}

pub fn get_local_cid() -> Result<u32, SystemError> {
	use libc::ioctl;
	let f = match File::open("/dev/vsock") {
		Ok(f) => f,
		Err(_e) => {
			return Err(SystemError {
				message: "Failed to open /dev/vsock".to_string(),
			});
		}
	};

	let mut cid = 0;
	let get_local_cid_result = unsafe {
		ioctl(f.as_raw_fd(), IOCTL_VM_SOCKETS_GET_LOCAL_CID, &mut cid)
	};

	if get_local_cid_result == -1 {
		return Err(SystemError {
			message: "Failed to fetch local CID".to_string(),
		});
	}
	Ok(cid)
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use super::*;

	/// A fake sysfs dir and hwrng device under a fresh temp dir.
	fn fake_hwrng(
		name: &str,
		rng_current: &str,
		rng_quality: &str,
		output: &[u8],
	) -> (PathBuf, PathBuf) {
		let dir = std::env::temp_dir()
			.join(format!("qos_system_hwrng_{}_{name}", std::process::id()));
		drop(std::fs::remove_dir_all(&dir));
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join("rng_current"), format!("{rng_current}\n"))
			.unwrap();
		std::fs::write(dir.join("rng_quality"), format!("{rng_quality}\n"))
			.unwrap();
		let dev = dir.join("hwrng");
		std::fs::write(&dev, output).unwrap();
		(dir, dev)
	}

	fn random_output() -> Vec<u8> {
		(0..2 * HWRNG_SAMPLE_LEN as u8).collect()
	}

	fn check(dir: &Path, dev: &Path) -> Result<HwrngSample, String> {
		check_hwrng_at(dir, dev, "nsm-hwrng", 1000).map_err(|e| e.message)
	}

	#[test]
	fn hwrng_accepts_expected_source_and_returns_its_output() {
		let output = random_output();
		let (dir, dev) = fake_hwrng("ok", "nsm-hwrng", "1000", &output);
		assert_eq!(check(&dir, &dev).map(|s| s.to_vec()), Ok(output));
	}

	#[test]
	fn hwrng_rejects_other_source() {
		let (dir, dev) =
			fake_hwrng("other", "virtio_rng.0", "1000", &random_output());
		assert_eq!(
			check(&dir, &dev),
			Err("Entropy source was virtio_rng.0 instead of nsm-hwrng".into())
		);
	}

	#[test]
	fn hwrng_rejects_wrong_quality() {
		let (dir, dev) =
			fake_hwrng("quality", "nsm-hwrng", "0", &random_output());
		assert_eq!(
			check(&dir, &dev),
			Err("Entropy source quality was 0 instead of 1000".into())
		);
	}

	#[test]
	fn hwrng_rejects_missing_sysfs() {
		let (dir, dev) = fake_hwrng("missing", "nsm-hwrng", "1000", &[]);
		std::fs::remove_file(dir.join("rng_quality")).unwrap();
		assert!(check(&dir, &dev).unwrap_err().starts_with("Failed to read"));
	}

	#[test]
	fn hwrng_rejects_short_read() {
		let (dir, dev) =
			fake_hwrng("short", "nsm-hwrng", "1000", &[1; HWRNG_SAMPLE_LEN]);
		assert!(check(&dir, &dev).unwrap_err().starts_with("Failed to read"));
	}

	#[test]
	fn hwrng_rejects_constant_output() {
		let (dir, dev) = fake_hwrng(
			"constant",
			"nsm-hwrng",
			"1000",
			&[0; 2 * HWRNG_SAMPLE_LEN],
		);
		assert_eq!(
			check(&dir, &dev),
			Err("Entropy source nsm-hwrng output is stuck".into())
		);
	}

	#[test]
	fn hwrng_rejects_repeated_output() {
		let block: Vec<u8> = (0..HWRNG_SAMPLE_LEN as u8).collect();
		let (dir, dev) = fake_hwrng(
			"repeated",
			"nsm-hwrng",
			"1000",
			&[block.clone(), block].concat(),
		);
		assert_eq!(
			check(&dir, &dev),
			Err("Entropy source nsm-hwrng output is stuck".into())
		);
	}
}
