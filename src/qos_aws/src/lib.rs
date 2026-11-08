use qos_system::{check_hwrng, dmesg, poweroff, reseed_crng};

/// Signal to Nitro hypervisor that booting was successful
fn nitro_heartbeat() {
	use libc::{AF_VSOCK, close, read, write};
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
	dmesg("Sent NSM heartbeat".to_string());
}

/// Initialize nitro device
pub fn init_platform() {
	// The NSM driver registers its hwrng with quality 1000. Reseeding puts NSM
	// output in the CRNG before anything generates keys. This runs before the
	// heartbeat, so a failure or hang shows up as a failed enclave boot.
	match check_hwrng("nsm-hwrng", 1000).and_then(|s| reseed_crng(&s)) {
		Ok(()) => {
			dmesg("Validated nsm-hwrng and reseeded the CRNG".to_string())
		}
		Err(e) => {
			eprintln!("{}", e);
			poweroff();
		}
	};

	nitro_heartbeat();
}
