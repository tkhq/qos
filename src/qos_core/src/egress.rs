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
	NixPath,
	errno::Errno,
	libc,
	sys::socket::{
		AddressFamily, Backlog, SockFlag, SockType, accept, bind, connect,
		listen, socket,
	},
	unistd::{read, write},
};

/// egress vsock port used both in and out of the enclave to provide transparent egress data transfer
pub const EGRESS_VSOCK_PORT: u32 = 1000; // reserved range so user ports don't interfere

/// Egress bridge errors.
#[derive(Debug)]
pub enum EgressError {
	/// `nix` syscall error.
	Nix(nix::Error),
	/// Standard I/O error.
	Io(std::io::Error),
	/// TUN socket setup failed.
	TunSocket(String),
	/// A pipe worker panicked.
	WorkerPanic(&'static str),
	/// Peer disconnected unexpectedly.
	UnexpectedDisconnect,
	/// A write returned zero bytes.
	WriteZero,
	/// Invalid IP frame.
	InvalidIpFrame,
}

impl From<nix::Error> for EgressError {
	fn from(value: nix::Error) -> Self {
		Self::Nix(value)
	}
}

impl From<std::io::Error> for EgressError {
	fn from(value: std::io::Error) -> Self {
		Self::Io(value)
	}
}

/// sets up required tuntap interfaces using the `ip` binary
/// opens one enclave side egress bridging session using given cid and port.
///
/// Returning from this function is the restart boundary. Callers should retry
/// by calling it again so all session fds, including the vsock fd, are
/// recreated from scratch.
/// # Errors
/// returns on socket errors of any kind
#[allow(unsafe_code)]
pub fn enclave_egress(
	cid: u32,
	port: u32,
	flags: u8,
) -> Result<(), EgressError> {
	let addr = SocketAddress::new_vsock_raw(cid, port, flags);
	let core_socket = create_core_socket()?;

	bind(core_socket.as_raw_fd(), &addr)?;

	// rust stdlib uses a 128 connection backlog
	listen(&core_socket, Backlog::new(1)?)?;

	let stream_fd = accept(core_socket.as_raw_fd())?;
	let stream = unsafe { OwnedFd::from_raw_fd(stream_fd) };
	let sock_fd = create_tun_socket("enclave_egress")
		.map_err(|err| EgressError::TunSocket(err.to_string()))?;
	copy_bidirectional(sock_fd, stream)
}

/// opens one host side egress bridging session at the specified address.
///
/// Returning from this function is the restart boundary. Callers should retry
/// by calling it again so all session fds, including the vsock fd, are
/// recreated from scratch.
/// # Errors
/// returns on socket errors of any kind
pub fn host_egress(cid: u32, port: u32, flags: u8) -> Result<(), EgressError> {
	let proxy_fd = connect_vsock_with_retry(cid, port, flags)?;
	let sock_fd = create_tun_socket("host_egress")
		.map_err(|err| EgressError::TunSocket(err.to_string()))?;

	copy_bidirectional(sock_fd, proxy_fd)
}

fn connect_vsock_with_retry(
	cid: u32,
	port: u32,
	flags: u8,
) -> Result<OwnedFd, EgressError> {
	loop {
		let addr = SocketAddress::new_vsock_raw(cid, port, flags);
		// Create a fresh vsock fd for every attempt. Reusing a vsock fd after a
		// failed pre-listener connect can poison the later connection.
		let proxy_fd = create_core_socket()?;

		if connect(proxy_fd.as_raw_fd(), &addr).is_ok() {
			return Ok(proxy_fd);
		}
		std::thread::sleep(Duration::from_millis(200));
	}
}

/// sets up new tuntap tun interface `enclave_egress` with localhost routing using `10.0.0.1/32` mask and default gw
/// expects `/usr/sbin/ip` and `/lib/ld-musl-x86` to be present
/// # Panics
/// panics if the program executions fail
pub fn init_egress_tun() {
	run_ip("tuntap add enclave_egress mode tun", "tuntap add failed");
	run_ip("link set lo up", "unable to bring up lo");
	run_ip("address add 10.0.0.1/32 dev lo", "ip assign to lo failed");
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
		let ret = nix::libc::ioctl(fd, 0x4004_54ca, &raw const ifr);
		if ret < 0 {
			libc::close(fd);
			return Err(Box::new(std::io::Error::last_os_error()));
		}

		Ok(OwnedFd::from_raw_fd(fd))
	}
}

/// Copies traffic in both directions between two sockets using threads.
///
/// Returns when either direction fails or disconnects, after cancelling and
/// joining the sibling worker.
fn copy_bidirectional(
	rsock: OwnedFd,
	vsock: OwnedFd,
) -> Result<(), EgressError> {
	set_nonblocking(rsock.as_fd())?;
	set_nonblocking(vsock.as_fd())?;
	let (cancel_read, cancel_write) = cancellation_pipe()?;

	let result = std::thread::scope(|s| {
		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let cancel = cancel_read.as_fd();
		let mut raw_to_vsock = Some(
			std::thread::Builder::new()
				.name("raw_to_vsock".to_owned())
				.spawn_scoped(s, move || pipe_all(sfd, tfd, cancel))?,
		);

		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let cancel = cancel_read.as_fd();
		let mut vsock_to_raw = match std::thread::Builder::new()
			.name("vsock_to_raw".to_owned())
			.spawn_scoped(s, move || pipe_frames(tfd, sfd, cancel))
		{
			Ok(worker) => Some(worker),
			Err(err) => {
				signal_cancel(cancel_write.as_fd());
				if let Some(worker) = raw_to_vsock {
					join_pipe_worker("raw_to_vsock", worker)?;
				}
				return Err(err.into());
			}
		};

		let first_result;
		loop {
			if raw_to_vsock.as_ref().is_some_and(|worker| worker.is_finished())
			{
				first_result = join_pipe_worker(
					"raw_to_vsock",
					raw_to_vsock.take().expect("worker exists"),
				);
				break;
			}

			if vsock_to_raw.as_ref().is_some_and(|worker| worker.is_finished())
			{
				first_result = join_pipe_worker(
					"vsock_to_raw",
					vsock_to_raw.take().expect("worker exists"),
				);
				break;
			}

			std::thread::sleep(Duration::from_millis(200));
		}

		signal_cancel(cancel_write.as_fd());

		if let Some(worker) = raw_to_vsock {
			join_pipe_worker("raw_to_vsock", worker)?;
		}
		if let Some(worker) = vsock_to_raw {
			join_pipe_worker("vsock_to_raw", worker)?;
		}

		first_result
	});

	drop(rsock);
	drop(vsock);

	result
}

/// sends all traffic from `fd_from` to `fd_to` byte by byte
fn pipe_all(
	fd_from: BorrowedFd,
	fd_to: BorrowedFd,
	cancel: BorrowedFd,
) -> Result<(), EgressError> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];

	loop {
		let Some(received) = read_with_cancel(fd_from, &mut buf, cancel)?
		else {
			return Ok(());
		};

		write_all_with_cancel(fd_to, &buf[..received], cancel)?;
	}
}

// returns Some(size) of the first ip frame present in `buf` or None if no complete frame is found
// WARNING: assumes `buf` slice starts at frame boundary!
fn next_frame(buf: &[u8]) -> Result<Option<usize>, EgressError> {
	let Ok((ip, _)) = etherparse::LaxIpSlice::from_slice(buf) else {
		return Ok(None);
	};

	let size: usize = if let Some(ip4) = ip.ipv4() {
		ip4.header().total_len()
	} else if let Some(ip6) = ip.ipv6() {
		ip6.header().payload_length() + 40 // ip6 40 bytes header + payload_length
	} else {
		return Err(EgressError::InvalidIpFrame);
	}
	.into();

	if buf.len() < size { Ok(None) } else { Ok(Some(size)) }
}

// sends all traffic from fd_from to fd_to byte by ip frames waiting for completion on reads
fn pipe_frames(
	fd_from: BorrowedFd,
	fd_to: BorrowedFd,
	cancel: BorrowedFd,
) -> Result<(), EgressError> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];
	let mut frame_size;
	let mut received = 0;

	loop {
		loop {
			if received == buf.len() {
				return Err(EgressError::InvalidIpFrame);
			}

			let Some(r) =
				read_with_cancel(fd_from, &mut buf[received..], cancel)?
			else {
				return Ok(());
			};
			received += r;

			if let Some(size) = next_frame(&buf[..received])? {
				frame_size = size;
				break;
			}
		}

		let mut sent = 0;
		loop {
			while sent < frame_size {
				let written =
					write_with_cancel(fd_to, &buf[sent..frame_size], cancel)?;
				if written == 0 {
					return Ok(());
				}
				sent += written;
			}

			if let Some(size) = next_frame(&buf[sent..received])? {
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

fn join_pipe_worker(
	name: &'static str,
	worker: std::thread::ScopedJoinHandle<'_, Result<(), EgressError>>,
) -> Result<(), EgressError> {
	worker.join().map_err(|_| EgressError::WorkerPanic(name))?
}

#[allow(unsafe_code)]
fn cancellation_pipe() -> Result<(OwnedFd, OwnedFd), EgressError> {
	let mut fds = [0; 2];
	let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
	if result < 0 {
		return Err(std::io::Error::last_os_error().into());
	}

	Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[allow(unsafe_code)]
fn signal_cancel(fd: BorrowedFd) {
	let byte = [1_u8];
	_ = unsafe {
		libc::write(fd.as_raw_fd(), byte.as_ptr().cast::<libc::c_void>(), 1)
	};
}

#[allow(unsafe_code)]
fn set_nonblocking(fd: BorrowedFd) -> Result<(), EgressError> {
	let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
	if flags < 0 {
		return Err(std::io::Error::last_os_error().into());
	}

	let result = unsafe {
		libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
	};
	if result < 0 {
		return Err(std::io::Error::last_os_error().into());
	}

	Ok(())
}

enum WaitResult {
	Ready,
	Cancelled,
}

fn wait_fd(
	fd: BorrowedFd,
	events: libc::c_short,
	cancel: BorrowedFd,
) -> Result<WaitResult, EgressError> {
	const POLL_FD_COUNT: libc::nfds_t = 2;

	let mut poll_fds = [
		libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 },
		libc::pollfd {
			fd: cancel.as_raw_fd(),
			events: libc::POLLIN,
			revents: 0,
		},
	];

	loop {
		for poll_fd in &mut poll_fds {
			poll_fd.revents = 0;
		}

		#[allow(unsafe_code)]
		let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), POLL_FD_COUNT, -1) };

		if result < 0 {
			let errno = Errno::last();
			if errno == Errno::EINTR {
				continue;
			}
			return Err(EgressError::Nix(errno));
		}

		if poll_fds[1].revents != 0 {
			return Ok(WaitResult::Cancelled);
		}

		if poll_fds[0].revents & libc::POLLNVAL != 0 {
			return Err(EgressError::Io(std::io::Error::from_raw_os_error(
				libc::EBADF,
			)));
		}

		if poll_fds[0].revents != 0 {
			return Ok(WaitResult::Ready);
		}
	}
}

fn read_with_cancel(
	fd: BorrowedFd,
	buf: &mut [u8],
	cancel: BorrowedFd,
) -> Result<Option<usize>, EgressError> {
	loop {
		if matches!(wait_fd(fd, libc::POLLIN, cancel)?, WaitResult::Cancelled) {
			return Ok(None);
		}

		match read(fd, buf) {
			Ok(0) => return Err(EgressError::UnexpectedDisconnect),
			Ok(size) => return Ok(Some(size)),
			Err(err) if err == Errno::EINTR || err == Errno::EAGAIN => {}
			Err(err) => return Err(EgressError::Nix(err)),
		}
	}
}

fn write_with_cancel(
	fd: BorrowedFd,
	buf: &[u8],
	cancel: BorrowedFd,
) -> Result<usize, EgressError> {
	loop {
		if matches!(wait_fd(fd, libc::POLLOUT, cancel)?, WaitResult::Cancelled)
		{
			return Ok(0);
		}

		match write(fd, buf) {
			Ok(0) => return Err(EgressError::WriteZero),
			Ok(size) => return Ok(size),
			Err(err) if err == Errno::EINTR || err == Errno::EAGAIN => {}
			Err(err) => return Err(EgressError::Nix(err)),
		}
	}
}

fn write_all_with_cancel(
	fd: BorrowedFd,
	buf: &[u8],
	cancel: BorrowedFd,
) -> Result<(), EgressError> {
	let mut sent = 0;
	while sent < buf.len() {
		let written = write_with_cancel(fd, &buf[sent..], cancel)?;
		if written == 0 {
			return Ok(());
		}
		sent += written;
	}
	Ok(())
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

/// run a statically linked program and return the `Child` handle
/// # Errors
/// returns `std::io::Error` in case of process creation problems
pub fn run_static(cmd_path: &str, args: &str) -> std::io::Result<Child> {
	Command::new(cmd_path).env_clear().args(args.split(' ')).spawn()
}

/// run a statically linked program in a loop
pub fn run_looping(cmd_path: &str, args: &str) {
	let cmd_path = cmd_path.to_owned();
	let args = args.to_owned();

	std::thread::spawn(move || {
		loop {
			match run_static(&cmd_path, &args) {
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

#[cfg(test)]
mod tests {
	use std::{
		os::fd::OwnedFd,
		os::unix::net::UnixStream,
		sync::{
			Arc,
			atomic::{AtomicBool, Ordering},
		},
		time::{Duration, Instant},
	};

	use super::{EgressError, copy_bidirectional};

	#[test]
	fn copy_bidirectional_returns_when_one_side_disconnects() {
		let (raw, _raw_peer) = UnixStream::pair().unwrap();
		let (vsock, vsock_peer) = UnixStream::pair().unwrap();
		let raw_fd: OwnedFd = raw.into();
		let vsock_fd: OwnedFd = vsock.into();
		let finished = Arc::new(AtomicBool::new(false));
		let finished_clone = Arc::clone(&finished);

		let worker = std::thread::spawn(move || {
			let result = copy_bidirectional(raw_fd, vsock_fd);
			finished_clone.store(true, Ordering::SeqCst);
			result
		});

		drop(vsock_peer);

		let start = Instant::now();
		while !finished.load(Ordering::SeqCst)
			&& start.elapsed() < Duration::from_secs(1)
		{
			std::thread::sleep(Duration::from_millis(10));
		}

		assert!(
			finished.load(Ordering::SeqCst),
			"copy_bidirectional did not wake the sibling pipe worker"
		);

		let result = match worker.join() {
			Ok(result) => result,
			Err(_) => panic!("worker panicked"),
		};
		assert!(matches!(result, Err(EgressError::UnexpectedDisconnect)));
	}
}
