//! Transparent egress functionality using linux tuntap and basic unix blocking syscalls

use std::{
	collections::HashMap,
	error::Error,
	ffi::CString,
	net::IpAddr,
	os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
	process::{Child, Command},
	sync::Mutex,
	time::{Duration, Instant},
};

use crate::io::SocketAddress;
use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};
use nix::{
	NixPath, libc,
	sys::socket::{
		AddressFamily, Backlog, SockFlag, SockType, accept, bind, connect,
		listen, socket,
	},
	unistd::{read, write},
};

pub use crate::EGRESS_VSOCK_PORT;

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
	let tracker = FlowTracker::default();
	copy_bidirectional(sock_fd, stream, Some(&tracker));
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

	copy_bidirectional(sock_fd, proxy_fd, None);
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
	run_ip("route replace default dev enclave_egress", "unable to route");
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

const FLOW_TIMEOUT: Duration = Duration::from_secs(300);
const FLOW_CAP: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
	protocol: u8,
	remote_ip: IpAddr,
	local_port: u16,
	remote_port: u16,
}

#[derive(Default)]
struct FlowTracker {
	flows: Mutex<HashMap<FlowKey, Instant>>,
}

impl FlowTracker {
	fn record_outbound(&self, frame: &[u8]) {
		self.record_outbound_at(frame, Instant::now());
	}

	fn record_outbound_at(&self, frame: &[u8], now: Instant) {
		let Some(key) = flow_key(frame, false) else {
			return;
		};
		let mut flows = self.flows.lock().expect("flow lock poisoned");
		if flows.len() >= FLOW_CAP && !flows.contains_key(&key) {
			flows.retain(|_, seen| now.duration_since(*seen) < FLOW_TIMEOUT);
			if flows.len() >= FLOW_CAP
				&& let Some(oldest) =
					flows.iter().min_by_key(|(_, seen)| **seen).map(|(k, _)| *k)
			{
				flows.remove(&oldest);
			}
		}
		flows.insert(key, now);
	}

	fn allows_inbound(&self, frame: &[u8]) -> bool {
		self.allows_inbound_at(frame, Instant::now())
	}

	fn allows_inbound_at(&self, frame: &[u8], now: Instant) -> bool {
		let Some(key) = flow_key(frame, true) else {
			return false;
		};
		self.flows
			.lock()
			.expect("flow lock poisoned")
			.get(&key)
			.is_some_and(|seen| now.duration_since(*seen) < FLOW_TIMEOUT)
	}
}

fn flow_key(frame: &[u8], inbound: bool) -> Option<FlowKey> {
	let packet = LaxSlicedPacket::from_ip(frame).ok()?;
	let (src_ip, dst_ip) = match packet.net.as_ref()? {
		LaxNetSlice::Ipv4(ip) => (
			IpAddr::V4(ip.header().source_addr()),
			IpAddr::V4(ip.header().destination_addr()),
		),
		LaxNetSlice::Ipv6(ip) => (
			IpAddr::V6(ip.header().source_addr()),
			IpAddr::V6(ip.header().destination_addr()),
		),
		LaxNetSlice::Arp(_) => return None,
	};
	let (protocol, src_port, dst_port) = match packet.transport.as_ref()? {
		TransportSlice::Tcp(tcp) => (
			etherparse::ip_number::TCP,
			tcp.source_port(),
			tcp.destination_port(),
		),
		TransportSlice::Udp(udp) => (
			etherparse::ip_number::UDP,
			udp.source_port(),
			udp.destination_port(),
		),
		TransportSlice::Icmpv4(_) => (etherparse::ip_number::ICMP, 0, 0),
		TransportSlice::Icmpv6(_) => (etherparse::ip_number::IPV6_ICMP, 0, 0),
	};
	Some(if inbound {
		FlowKey {
			protocol: protocol.0,
			remote_ip: src_ip,
			local_port: dst_port,
			remote_port: src_port,
		}
	} else {
		FlowKey {
			protocol: protocol.0,
			remote_ip: dst_ip,
			local_port: src_port,
			remote_port: dst_port,
		}
	})
}

/// Copies traffic in both directions between two sockets using threads, never returns
/// # Panics
/// Panics if any read/write operation fails
fn copy_bidirectional(
	rsock: OwnedFd,
	vsock: OwnedFd,
	tracker: Option<&FlowTracker>,
) {
	std::thread::scope(|s| {
		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let raw_to_vsock = std::thread::Builder::new()
			.name("raw_to_vsock".to_owned())
			.spawn_scoped(s, move || {
				pipe_all(sfd, tfd, tracker)
					.expect("error piping from raw to vsock");
			})
			.expect("unable to run scoped thread");

		let sfd = rsock.as_fd();
		let tfd = vsock.as_fd();
		let vsock_to_raw = std::thread::Builder::new()
			.name("vsock_to_raw".to_owned())
			.spawn_scoped(s, move || {
				pipe_frames(tfd, sfd, tracker)
					.expect("error piping from vsock to raw");
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
fn pipe_all(
	fd_from: BorrowedFd,
	fd_to: BorrowedFd,
	tracker: Option<&FlowTracker>,
) -> Result<(), nix::Error> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];

	loop {
		let received = read(fd_from, &mut buf)?;
		assert!(received > 0, "unexpected disconnect from socket");

		if let Some(tracker) = tracker {
			tracker.record_outbound(&buf[..received]);
		}

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
	tracker: Option<&FlowTracker>,
) -> Result<(), nix::Error> {
	// NOTE: qemu has the same bug as aws nitro
	#[allow(clippy::large_stack_arrays)]
	let mut buf = [0u8; 32000];
	let mut received = 0;

	loop {
		let r = read(fd_from, &mut buf[received..])?;
		assert!(r > 0, "unexpected disconnect from socket");
		received += r;

		let mut offset = 0;
		while let Some(size) = next_frame(&buf[offset..received]) {
			let end = offset + size;
			if tracker.is_none_or(|t| t.allows_inbound(&buf[offset..end])) {
				let mut sent = offset;
				while sent < end {
					sent += write(fd_to, &buf[sent..end])?;
				}
			}
			offset = end;
		}

		if offset > 0 {
			buf.copy_within(offset..received, 0);
			received -= offset;
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

#[cfg(test)]
mod tests {
	use super::*;
	use etherparse::{Ipv4Header, TcpHeader, UdpHeader, ip_number};

	const ENCLAVE_IP: [u8; 4] = [169, 254, 0, 1];
	const REMOTE_IP: [u8; 4] = [93, 184, 216, 34];

	fn tcp_frame(
		src: [u8; 4],
		dst: [u8; 4],
		src_port: u16,
		dst_port: u16,
		syn: bool,
	) -> Vec<u8> {
		let mut tcp = TcpHeader::new(src_port, dst_port, 0, 1024);
		tcp.syn = syn;
		let ip =
			Ipv4Header::new(tcp.header_len_u16(), 64, ip_number::TCP, src, dst)
				.unwrap();
		let mut frame = ip.to_bytes().to_vec();
		frame.extend(tcp.to_bytes());
		frame
	}

	fn udp_frame(
		src: [u8; 4],
		dst: [u8; 4],
		src_port: u16,
		dst_port: u16,
	) -> Vec<u8> {
		let udp_len = u16::try_from(UdpHeader::LEN).unwrap();
		let udp = UdpHeader {
			source_port: src_port,
			destination_port: dst_port,
			length: udp_len,
			checksum: 0,
		};
		let ip =
			Ipv4Header::new(udp_len, 64, ip_number::UDP, src, dst).unwrap();
		let mut frame = ip.to_bytes().to_vec();
		frame.extend(udp.to_bytes());
		frame
	}

	#[test]
	fn unsolicited_inbound_frames_are_rejected() {
		let tracker = FlowTracker::default();

		let tcp_syn = tcp_frame(REMOTE_IP, ENCLAVE_IP, 40000, 8080, true);
		assert!(!tracker.allows_inbound(&tcp_syn));

		let udp = udp_frame(REMOTE_IP, ENCLAVE_IP, 40000, 5353);
		assert!(!tracker.allows_inbound(&udp));

		assert!(!tracker.allows_inbound(&[0u8; 40]));
	}

	#[test]
	fn replies_to_enclave_originated_tcp_flow_are_allowed() {
		let tracker = FlowTracker::default();
		let outbound = tcp_frame(ENCLAVE_IP, REMOTE_IP, 44000, 443, true);
		tracker.record_outbound(&outbound);

		let reply = tcp_frame(REMOTE_IP, ENCLAVE_IP, 443, 44000, false);
		assert!(tracker.allows_inbound(&reply));

		let wrong_port = tcp_frame(REMOTE_IP, ENCLAVE_IP, 443, 44001, false);
		assert!(!tracker.allows_inbound(&wrong_port));

		let wrong_ip = tcp_frame([8, 8, 8, 8], ENCLAVE_IP, 443, 44000, false);
		assert!(!tracker.allows_inbound(&wrong_ip));

		let wrong_protocol = udp_frame(REMOTE_IP, ENCLAVE_IP, 443, 44000);
		assert!(!tracker.allows_inbound(&wrong_protocol));
	}

	#[test]
	fn replies_to_enclave_originated_udp_flow_are_allowed() {
		let tracker = FlowTracker::default();
		let query = udp_frame(ENCLAVE_IP, REMOTE_IP, 51000, 53);
		tracker.record_outbound(&query);

		let response = udp_frame(REMOTE_IP, ENCLAVE_IP, 53, 51000);
		assert!(tracker.allows_inbound(&response));
	}

	#[test]
	fn idle_flows_expire() {
		let tracker = FlowTracker::default();
		let start = Instant::now();
		let outbound = udp_frame(ENCLAVE_IP, REMOTE_IP, 51000, 53);
		tracker.record_outbound_at(&outbound, start);

		let response = udp_frame(REMOTE_IP, ENCLAVE_IP, 53, 51000);
		assert!(tracker.allows_inbound_at(&response, start));
		assert!(!tracker.allows_inbound_at(&response, start + FLOW_TIMEOUT));
	}

	#[test]
	fn pipe_frames_forwards_only_tracked_flows() {
		let (in_read, in_write) = nix::unistd::pipe().unwrap();
		let (out_read, out_write) = nix::unistd::pipe().unwrap();

		let tracker = std::sync::Arc::new(FlowTracker::default());
		let outbound = tcp_frame(ENCLAVE_IP, REMOTE_IP, 44000, 443, true);
		tracker.record_outbound(&outbound);

		let piping_tracker = tracker.clone();
		std::thread::spawn(move || {
			let _ = pipe_frames(
				in_read.as_fd(),
				out_write.as_fd(),
				Some(&piping_tracker),
			);
		});

		let unsolicited = tcp_frame(REMOTE_IP, ENCLAVE_IP, 40000, 8080, true);
		let allowed = tcp_frame(REMOTE_IP, ENCLAVE_IP, 443, 44000, false);
		let mut input = unsolicited;
		input.extend(&allowed);
		let mut written = 0;
		while written < input.len() {
			written += write(&in_write, &input[written..]).unwrap();
		}

		let mut forwarded = vec![0u8; allowed.len()];
		let mut received = 0;
		while received < forwarded.len() {
			received += read(&out_read, &mut forwarded[received..]).unwrap();
		}
		assert_eq!(forwarded, allowed);
		std::mem::forget(in_write);
	}
}
