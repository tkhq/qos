// //! Basic struct for creating a VSOCK (hypervisor guest communication) streaming
// //! socket.
// // This code is largely adapted from veracruz - zeke

// use std::os::unix::io::{AsRawFd, RawFd};

// use nix::{
// 	sys::socket::{
// 		connect, setsockopt, shutdown, socket, sockopt, AddressFamily,
// 		Shutdown, SockFlag, SockType, VsockAddr,
// 	},
// 	unistd::close,
// };

// /// Max number of attempts to retry connecting.
// const MAX_RETRY: usize = 8;
// const BACKLOG: usize = 128;

// pub struct VsockSocket {
// 	/// The file handle of the VSOCK.
// 	socket_fd: RawFd,
// }

// impl VsockSocket {
// 	#[inline]
// 	/// Create a new [`VsockSocket`] from a [`RawFd`].
// 	fn new(socket_fd: RawFd) -> Self {
// 		VsockSocket { socket_fd }
// 	}

// 	// / Initiate a connection on an VSOCK. Fails if the connection
// 	// / cannot be made after `MAX_RETRY` attempts.
// 	// /
// 	// / Uses exponential back-off to wait between different attempts to
// 	// connect.
// 	pub fn try_connect(cid: u32, port: u32) -> Result<Self, nix::Error> {
// 		let sockaddr = VsockAddr::new(cid, port);

// 		let mut err = nix::Error::UnknownErrno;

// 		for i in 0..MAX_RETRY {
// 			// https://man7.org/linux/man-pages/man7/socket.7.html
// 			// Create a socket file descriptor
// 			let socket_endpoint_fd = socket(
// 				// Domain - VSOCK hypervisor guest communication
// 				AddressFamily::Vsock,
// 				// Type - sequenced, two way byte stream. (full duplexed).
// 				// Stream must be in a connected state before send/recieve.
// 				SockType::Stream,
// 				// Flags
// 				SockFlag::empty(),
// 				// Protocol - no protocol needs to be specified as SOCK_STREAM
// 				// is both a type and protocol.
// 				None,
// 			)?;
// 			println!("socket_endpoint_fd={}", socket_endpoint_fd);
// 			let vsock = VsockSocket::new(socket_endpoint_fd);

// 			// Allow multiple sockets to bind to the same local address
// 			setsockopt(vsock.as_raw_fd(), sockopt::ReuseAddr, &true)?;
// 			// Allow multiple sockets to bind to the same port. Helpful for
// 			// allowing multiple threads bind to the same port.
// 			setsockopt(vsock.as_raw_fd(), sockopt::ReusePort, &true)?;

// 			// https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html
// 			// Attempt to connect to the socket
// 			match connect(vsock.as_raw_fd(), &sockaddr) {
// 				Ok(_) => return Ok(vsock),
// 				Err(e) => err = e,
// 			}

// 			// Exponentially back off before reattempting connection
// 			std::thread::sleep(std::time::Duration::from_secs(1 << i));
// 		}

// 		Err(err)
// 	}

// 	// https://vdc-download.vmware.com/vmwb-repository/dcr-public/a49be05e-fa6d-4da1-9186-922fbfef149e/a65f3c51-aaeb-476d-80c3-827b805c2f9e/ws9_esx60_vmci_sockets.pdf
// 	// socket -> bind -> listen -> accept .... select -> recv, send etc .... close
// 	pub fn try_listen(cid: u32, port: u32) -> Result<Self, nix::Error> {
// 		let sockaddr = VsockAddr::new(cid, port);
// 		let socket_endpoint_fd = Self::socket_endpoint_fd()?;
// 		println!("sockaddr={}", sockaddr);
// 		println!("socket_endpoint_fd={}", socket_endpoint_fd);

// 		nix::sys::socket::bind(socket_endpoint_fd, &sockaddr)?;

// 		nix::sys::socket::listen(socket_endpoint_fd, BACKLOG)?;

// 		let new_fd = nix::sys::socket::accept(socket_endpoint_fd)?;
// 		println!("new_fd={}", new_fd);

// 		Ok(VsockSocket::new(socket_endpoint_fd))
// 	}

// 	fn socket_endpoint_fd() -> Result<RawFd, nix::Error> {
// 		socket(
// 			// Domain - VSOCK hypervisor guest communication
// 			AddressFamily::Vsock,
// 			// Type - sequenced, two way byte stream. (full duplexed).
// 			// Stream must be in a connected state before send/recieve.
// 			SockType::Stream,
// 			// Flags
// 			SockFlag::empty(),
// 			// Protocol - no protocol needs to be specified as SOCK_STREAM
// 			// is both a type and protocol.
// 			None,
// 		)
// 	}
// }

// impl Drop for VsockSocket {
// 	/// Attempt to close the socket on drop.
// 	///
// 	/// If shutdown or closing fail, a message will be sent to stderr, but
// 	/// nothing else is done.
// 	fn drop(&mut self) {
// 		// https://man7.org/linux/man-pages/man2/shutdown.2.html
// 		// Dissallow READ (further receptions) and WRITE (further transmissions)
// 		shutdown(self.socket_fd, Shutdown::Both).unwrap_or_else(|e| {
// 			eprintln!("Failed to shutdown vsocket: {:?}", e)
// 		});

// 		// https://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html
// 		// Destroy the socket.
// 		// Need to be careful not to close a raw fd that already implicitly
// 		// closes on drop as it causes a double close condition, leading to
// 		// confusing errors. Here the raw fd is consumed, so it shouldn't be
// 		// implicitly dropped.
// 		close(self.socket_fd)
// 			.unwrap_or_else(|e| eprintln!("Failed to close vsocket: {:?}", e));
// 	}
// }

// impl AsRawFd for VsockSocket {
// 	#[inline]
// 	/// Extract the raw RadFd from the VsockSocket
// 	fn as_raw_fd(&self) -> RawFd {
// 		self.socket_fd
// 	}
// }
