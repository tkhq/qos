//! Basic struct for creating a VSOCK (hypervisor guest communication) streaming
//! socket.
// This code is largely adapted from veracruz - zeke

use std::os::unix::io::{AsRawFd, RawFd};

use nix::{
	sys::socket::{
		bind, connect, accept, listen, shutdown, socket, AddressFamily,
		Shutdown, SockFlag, SockType, SockaddrLike
	},
	unistd::close,
};

use super::IOError;

#[cfg(feature="vm")]
use nix::sys::socket::VsockAddr;

#[cfg(feature = "local")]
use nix::sys::socket::UnixAddr;

/// Max number of attempts to retry connecting.
const MAX_RETRY: usize = 8;
const BACKLOG: usize = 128;

pub struct StreamEndpoint {
	fd: RawFd,
}

impl StreamEndpoint {
  pub fn try_connect(addr: &dyn SockaddrLike) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for i in 0..MAX_RETRY {
			let fd = Self::socket_endpoint_fd(addr)?;
			let endpoint = StreamEndpoint { fd };

			// setsockopt(vsock.as_raw_fd(), sockopt::ReuseAddr, &true)?;
			// setsockopt(vsock.as_raw_fd(), sockopt::ReusePort, &true)?;

			match connect(endpoint.fd, addr) {
				Ok(_) => return Ok(endpoint),
				Err(e) => err = IOError::NixError(e),
			}

			// Exponentially back off before reattempting connection
			std::thread::sleep(std::time::Duration::from_secs(1 << i));
		}

		Err(err)
	}

	// https://vdc-download.vmware.com/vmwb-repository/dcr-public/a49be05e-fa6d-4da1-9186-922fbfef149e/a65f3c51-aaeb-476d-80c3-827b805c2f9e/ws9_esx60_vmci_sockets.pdf
	// socket -> bind -> listen -> accept .... select -> recv, send etc .... close
	pub fn try_listen(addr: &dyn SockaddrLike) -> Result<Self, IOError> {
		let fd = Self::socket_endpoint_fd(addr)?;

		bind(fd, addr).map_err(|e| IOError::NixError(e))?;
		listen(fd, BACKLOG).map_err(|e| IOError::NixError(e))?;
		// New file descriptor with connection to client
		let fd = accept(fd).map_err(|e| IOError::NixError(e))?;

		Ok(StreamEndpoint{fd})
	}

	fn socket_endpoint_fd(addr: &dyn SockaddrLike) -> Result<RawFd, IOError> {
		let addr_family = match addr.family() {
			Some(AddressFamily::Unix) =>  AddressFamily::Unix ,
			#[cfg(feature = "vm")]
			Some(AddressFamily::Vsock) => AddressFamily::Vsock,
			_ => return Err(IOError::UnsupportedAddr),
		};

		socket(
			addr_family,
			// Type - sequenced, two way byte stream. (full duplexed).
			// Stream must be in a connected state before send/recieve.
			SockType::Stream,
			// Flags
			SockFlag::empty(),
			// Protocol - no protocol needs to be specified as SOCK_STREAM
			// is both a type and protocol.
			None,
		).map_err(|e| IOError::NixError(e))
	}
}

impl Drop for StreamEndpoint {
	// TODO: check if other file descriptors need to be shutdown/closed
	fn drop(&mut self) {
		shutdown(self.fd, Shutdown::Both).unwrap_or_else(|e| {
			eprintln!("Failed to shutdown socket: {:?}", e)
		});
		close(self.fd)
			.unwrap_or_else(|e| eprintln!("Failed to close socket: {:?}", e));
	}
}