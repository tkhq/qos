use std::ffi::c_void;

use nix::libc::{
	htonl, ifreq, memcpy, sockaddr, sockaddr_in, socket, AF_INET, IFF_UP,
	SIOCGIFFLAGS, SIOCSIFADDR, SIOCSIFFLAGS, SOCK_DGRAM,
};
use nix::{ioctl_read_bad, ioctl_write_ptr_bad};

const LOCALHOST_U32: u32 = 2130706433; // little endian 127.0.0.1 needs htonl

pub fn init_localhost() {
	// create the dgram setter socket
	let sockfd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
	if sockfd == -1 {
		panic!("unable to create dgram socket");
	}

	// prep the localhost sockaddr_in with 127.0.0.1 value
	let sin = sockaddr_in {
		sin_family: AF_INET as u16,
		sin_port: 0,
		sin_addr: nix::libc::in_addr { s_addr: htonl(LOCALHOST_U32) },
		sin_zero: [0u8; 8],
	};

	// interface name b"lo" as [i16; 16] for ioctl purposes
	let ifr_name: [i8; 16] =
		[108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

	let mut ifr: ifreq = unsafe { std::mem::zeroed() };
	ifr.ifr_name = ifr_name;

	// setup ioctl to get current flags for the "lo" interface
	ioctl_read_bad!(sio_cgi_fflags, SIOCGIFFLAGS, ifreq);

	// setup ioctl to set flags for the "lo" interface
	ioctl_write_ptr_bad!(sio_csi_fflags, SIOCSIFFLAGS, ifreq);

	// setup ioctl to set address for the "lo" interface
	ioctl_write_ptr_bad!(sio_csi_faddr, SIOCSIFADDR, ifreq);

	unsafe {
		// get the current flags for "lo" interface
		match sio_cgi_fflags(sockfd, &mut ifr) {
			Err(err) => {
				panic!("unable to read interface flags, errno: {}", err)
			}
			Ok(r) => println!("sio_cgi_fflags result: {r}"),
		}
		// flag "lo" interface to up if it wasn't
		if (ifr.ifr_ifru.ifru_flags | !(IFF_UP as i16)) != 0 {
			println!("interface offline, brinding it up");
			ifr.ifr_ifru.ifru_flags |= IFF_UP as i16;
			match sio_csi_fflags(sockfd, &ifr) {
				Err(err) => {
					panic!("unable to set interface flags, errno: {}", err)
				}
				Ok(r) => println!("sio_csi_fflags result: {r}"),
			}
		}
		// assign localhost ip address to the "lo" interface flags struct
		let dest = &mut ifr.ifr_ifru.ifru_addr as *mut sockaddr as *mut c_void;
		let src = &sin as *const sockaddr_in as *const c_void;
		memcpy(dest, src, size_of::<sockaddr>());
		// set the ip address flags on the "lo" interface
		match sio_csi_faddr(sockfd, &ifr) {
			Err(err) => {
				panic!("unable to set interface address, errno: {}", err)
			}
			Ok(r) => println!("sio_csi_faddr result: {r}"),
		}
	}
}
