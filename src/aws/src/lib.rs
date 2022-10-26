use system::{dmesg, SystemError};

// Signal to Nitro hypervisor that booting was successful
fn nitro_heartbeat() {
	use libc::{close, read, write, AF_VSOCK};
	use system::socket_connect;
	let mut buf: [u8; 1] = [0; 1];
	buf[0] = 0xB7; // AWS Nitro heartbeat value
	let fd = match socket_connect(AF_VSOCK, 9000, 3) {
		Ok(f) => f,
		Err(e) => {
			eprintln!("{}", e);
			return;
		}
	};
	unsafe {
		write(fd, buf.as_ptr() as _, 1);
		read(fd, buf.as_ptr() as _, 1);
		close(fd);
	}
	dmesg(format!("Sent NSM heartbeat"));
}

// Get entropy sample from Nitro device
pub fn get_entropy(size: usize) -> Result<Vec<u8>, SystemError> {
	use nsm_api::api::ErrorCode;
	use nsm_lib::{nsm_get_random, nsm_lib_init};
	let nsm_fd = nsm_lib_init();
	if nsm_fd < 0 {
		return Err(SystemError {
			message: String::from("Failed to connect to NSM device"),
		});
	};
	let mut dest = Vec::with_capacity(size);
	while dest.len() < size {
		let mut buf = [0u8; 256];
		let mut buf_len = buf.len();
		let status =
			unsafe { nsm_get_random(nsm_fd, buf.as_mut_ptr(), &mut buf_len) };
		match status {
			ErrorCode::Success => {
				dest.extend_from_slice(&buf);
			}
			_ => {
				return Err(SystemError {
					message: String::from(
						"Failed to get entropy from NSM device",
					),
				});
			}
		};
	}
	Ok(dest)
}

// Initialize nitro device
pub fn init_platform() {
	use system::insmod;
	// TODO: error handling
	nitro_heartbeat();

	match insmod("/nsm.ko") {
		Ok(()) => dmesg(format!("Loaded nsm.ko")),
		Err(e) => eprintln!("{}", e),
	};
}
