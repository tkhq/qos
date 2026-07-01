//! Transparent egress functionality using linux tuntap and basic unix blocking syscalls

use std::{
	error::Error,
	ffi::CString,
	os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
	process::{Child, Command},
	time::Duration,
};

use crate::io::SocketAddress;
use nix::{
	NixPath, libc,
	sys::socket::{
		AddressFamily, Backlog, SockFlag, SockType, accept, bind, connect,
		listen, socket,
	},
	unistd::{read, write},
};

/// Vsock port used to connect enclave egress to host egress
pub const EGRESS_VSOCK_PORT: u32 = 2001;

/// opens enclave side egress bridging using given cid and port blocking forever
/// # Panics
/// panics on socket errors of any kind
#[allow(unsafe_code)]
pub fn enclave_egress(cid: u32, port: u32, flags: u8) {
	eprintln!(
		"qos_bridge: enclave egress running cid: {cid} port: {port} flags: {flags:02x}"
	);
	let addr = SocketAddress::new_vsock_raw(cid, port, flags);
	let core_socket =
		create_core_socket().expect("unable to create core socket");

	bind(core_socket.as_raw_fd(), &addr).expect("unable to bind core socket");

	// rust stdlib uses a 128 connection backlog
	listen(&core_socket, Backlog::new(1).expect("unable to set backlog"))
		.expect("unable to listen on core socket");

	let stream_fd = accept(core_socket.as_raw_fd())
		.expect("unable to accept on core socket");
	let stream = unsafe { OwnedFd::from_raw_fd(stream_fd) };
	let sock_fd = create_tun_socket("enclave_egress")
		.expect("unable to create raw socket");
	copy_bidirectional(sock_fd, stream);
}

/// opens host side egress bridging at the specified address, blocking forever
/// # Panics
/// panics on socket errors of any kind
pub fn host_egress(cid: u32, port: u32, flags: u8) {
	eprintln!(
		"qos_bridge: host egress running cid: {cid} port: {port} flags: {flags:02x}"
	);
	// NOTE: it's important we don't loop just connect here as that seems to cause EPIPE errors after it does connect
	let proxy_fd = loop {
		let addr = SocketAddress::new_vsock_raw(cid, port, flags);
		let proxy_fd = create_core_socket().expect("unable to create vsock");

		if connect(proxy_fd.as_raw_fd(), &addr).is_ok() {
			break proxy_fd;
		}
		std::thread::sleep(Duration::from_millis(200));
	};

	let sock_fd =
		create_tun_socket("host_egress").expect("unable to create raw socket");

	copy_bidirectional(sock_fd, proxy_fd);
}

/// sets up new tuntap tun interface `enclave_egress` with localhost routing using `169.254.0.1/32` mask and default gw
/// expects `/usr/sbin/ip` and `/lib/ld-musl-x86` to be present
/// # Panics
/// panics if the program executions fail
pub fn init_egress_tun() {
	run_ip("tuntap add enclave_egress mode tun", "tuntap add failed");
	run_ip("link set lo up", "unable to bring up lo");
	run_ip("address add 169.254.0.1/32 dev lo", "ip assign to lo failed"); // use link-local ip
	run_ip("link set mtu 1320 dev enclave_egress", "unable to set MTU size"); // MTU 1340 is max for calico wg-v6-cali so we need <= to that
	run_ip("link set enclave_egress up", "unable to bring up egress");
	run_ip("route add default dev enclave_egress", "unable to route");
}

/// Create core vsock socket in streaming mode
/// # Returns
/// returns the new `OwnedFd` vsock
/// # Errors
/// same as `socket` from `nix`
pub fn create_core_socket() -> Result<OwnedFd, nix::Error> {
	socket(AddressFamily::Vsock, SockType::Stream, SockFlag::empty(), None)
}

/// Create a raw socket connecting to the given linux tun interface
/// # Returns
/// returns the new `OwnedFd` raw socket
/// # Errors
/// returns `NilError` in case of `CString` failure, or `std::io::Error` from `libc::errno` if `open` or `ioctl` have failed
#[allow(unsafe_code)]
#[allow(clippy::cast_possible_truncation)]
pub fn create_tun_socket(if_name: &str) -> Result<OwnedFd, Box<dyn Error>> {
	let if_name = CString::new(if_name)?;
	let name_ptr = if_name.as_ptr();
	let name_len = if_name.len().min(nix::libc::IFNAMSIZ - 1);
	let mut ifr = libc::ifreq {
		ifr_name: [0; nix::libc::IFNAMSIZ],
		ifr_ifru: unsafe { std::mem::zeroed() },
	};

	let tun_dev = CString::new("/dev/net/tun")?;

	unsafe {
		let fd = libc::open(tun_dev.as_ptr(), libc::O_RDWR);
		if fd < 0 {
			return Err(Box::new(std::io::Error::last_os_error()));
		}
		std::ptr::copy_nonoverlapping(
			name_ptr,
			ifr.ifr_name.as_mut_ptr(),
			name_len,
		);
		ifr.ifr_ifru.ifru_flags = libc::IFF_TUN as i16 | libc::IFF_NO_PI as i16;

		// Set flags to IFF_TUN
		// Using libc directly for the ioctl is common when nix lacks the specific macro:
		let ret = nix::libc::ioctl(fd, 0x4004_54ca, &raw mut ifr);
		if ret < 0 {
			libc::close(fd);
			return Err(Box::new(std::io::Error::last_os_error()));
		}

		Ok(OwnedFd::from_raw_fd(fd))
	}
}

/// Copies traffic in both directions between two sockets using threads, never returns
/// # Panics
/// Panics if any read/write operation fails
fn copy_bidirectional(rsock: OwnedFd, vsock: OwnedFd) {
	std::thread::scope(|s| {
		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let raw_to_vsock = std::thread::Builder::new()
			.name("raw_to_vsock".to_owned())
			.spawn_scoped(s, move || {
				pipe_all(sfd, tfd).expect("error piping from raw to vsock");
			})
			.expect("unable to run scoped thread");

		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let vsock_to_raw = std::thread::Builder::new()
			.name("vsock_to_raw".to_owned())
			.spawn_scoped(s, move || {
				// pipe_all(tfd, sfd, TrafficDirection::VsockToRaw(debug))
				pipe_frames(tfd, sfd).expect("error piping from vsock to raw");
			})
			.expect("unable to run scoped thread");

		// see if any of the threads have paniced and if so, propagate the error and panic the main process
		loop {
			if raw_to_vsock.is_finished() {
				raw_to_vsock.join().expect("raw_to_vsock worker error");
				panic!("raw_to_vsock exit");
			}

			if vsock_to_raw.is_finished() {
				vsock_to_raw.join().expect("vsock_to_raw worker error");
				panic!("vsock_to_raw exit");
			}

			std::thread::sleep(Duration::from_millis(200));
		}
	});

	// mostly for lint, we want to consume here on purpose as copy_bidirectional is supposed to be a terminal function
	drop(rsock);
	drop(vsock);
}

/// sends all traffic from `fd_from` to `fd_to` byte by byte
/// # Panics
/// panics if reads receive 0
fn pipe_all(fd_from: BorrowedFd, fd_to: BorrowedFd) -> Result<(), nix::Error> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];

	loop {
		let received = read(fd_from, &mut buf)?;
		assert!(received > 0, "unexpected disconnect from socket");

		let mut sent = 0;
		while sent < received {
			sent += write(fd_to, &buf[sent..received])?;
		}
	}
}

// returns Some(size) of the first ip frame present in `buf` or None if no complete frame is found
// WARNING: assumes `buf` slice starts at frame boundary!
fn next_frame(buf: &[u8]) -> Option<usize> {
	let Ok((ip, _)) = etherparse::LaxIpSlice::from_slice(buf) else {
		return None;
	};

	let size: usize = if let Some(ip4) = ip.ipv4() {
		ip4.header().total_len()
	} else if let Some(ip6) = ip.ipv6() {
		ip6.header().payload_length() + 40 // ip6 40 bytes header + payload_length
	} else {
		panic!("invalid ip version??");
	}
	.into();

	if buf.len() < size { None } else { Some(size) }
}

// sends all traffic from fd_from to fd_to byte by ip frames waiting for completion on reads
fn pipe_frames(
	fd_from: BorrowedFd,
	fd_to: BorrowedFd,
) -> Result<(), nix::Error> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];
	let mut frame_size;
	let mut received = 0;

	loop {
		loop {
			let r = read(fd_from, &mut buf[received..])?;
			assert!(r > 0, "unexpected disconnect from socket");
			received += r;

			if let Some(size) = next_frame(&buf[..received]) {
				frame_size = size;
				break;
			}
		}

		let mut sent = 0;
		loop {
			while sent < frame_size {
				sent += write(fd_to, &buf[sent..frame_size])?;
			}

			if let Some(size) = next_frame(&buf[sent..received]) {
				assert!(sent + size <= buf.len(), "frame buffer overflow"); // should be impossible as MTU is 1500
				frame_size = sent + size;
			} else {
				let tail_size = received - sent;
				// copy tail to start so we can continue on reads
				if sent < received {
					buf.rotate_left(sent);
				}
				received = tail_size;
				break;
			}
		}
	}
}

/// Default path to the `ip` utility program
pub const IP_PATH: &str = "/usr/sbin/ip";

/// run the `ip` utility via the `run_with_ld`
/// # Panics
/// panics on program spawn errors
pub fn run_ip(args: &str, fail_str: &str) {
	let ip_exit = run_with_ld(IP_PATH, args)
		.expect("unable to run ip command")
		.wait()
		.expect("ip program failed to finish");
	assert!(ip_exit.success(), "{}", fail_str);
}

/// run a statically linked program in a loop in a separate thread (not blocking)
pub fn run_looping(cmd_path: &str, args: &str) {
	let cmd_path = cmd_path.to_owned();
	let args: Vec<String> =
		args.split_whitespace().map(str::to_string).collect();

	std::thread::spawn(move || {
		loop {
			match Command::new(&cmd_path).env_clear().args(&args).spawn() {
				Ok(mut child) => {
					let exit = child.wait(); // try to wait, restart  in any case
					eprintln!("process {cmd_path} exit {exit:?}");
				}
				Err(err) => {
					eprintln!("error spawning process {cmd_path}: {err}");
				}
			}

			eprintln!("process {cmd_path} exited, restarting in 200ms");
			std::thread::sleep(Duration::from_millis(200));
		}
	});
}

/// run a program with `/lib/ld-musl-x86` loader and return the `Child` handle
/// # Errors
/// returns `std::io::Error` in case of process creation problems
pub fn run_with_ld(cmd_path: &str, args: &str) -> std::io::Result<Child> {
	Command::new("/lib/ld-musl-x86")
		.env_clear()
		.arg(cmd_path)
		.args(args.split(' '))
		.spawn()
}
