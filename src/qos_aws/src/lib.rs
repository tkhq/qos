use qos_system::{check_hwrng, dmesg, poweroff};

/// Signal to Nitro hypervisor that booting was successful
fn nitro_heartbeat() {
	use libc::{close, read, write, AF_VSOCK};
	use qos_system::socket_connect;
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

/// Initialize nitro device
pub fn init_platform() {
	use qos_system::insmod;
	nitro_heartbeat();

	match insmod("/nsm.ko") {
		Ok(()) => dmesg(format!("Loaded nsm.ko")),
		Err(e) => eprintln!("{}", e),
	};

	match check_hwrng("nsm-hwrng") {
		Ok(()) => dmesg(format!("Validated entropy source is nsm-hwrng")),
		Err(e) => {
			eprintln!("{}", e);
			poweroff();
		}
	};
}
