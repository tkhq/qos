//! Abstractions to handle connection based socket streams.

use std::{
	io::{ErrorKind, Read, Write},
	mem::size_of,
	os::unix::io::RawFd,
};

#[cfg(feature = "vm")]
use nix::sys::socket::VsockAddr;
pub use nix::sys::time::{TimeVal, TimeValLike};
use nix::{
	sys::socket::{
		accept, bind, connect, listen, recv, send, shutdown, socket, sockopt,
		AddressFamily, MsgFlags, SetSockOpt, Shutdown, SockFlag, SockType,
		SockaddrLike, UnixAddr,
	},
	unistd::close,
};

use super::IOError;

// 25(retries) x 10(milliseconds) = 1/4 a second of retrying
const MAX_RETRY: usize = 25;
const BACKOFF_MILLISECONDS: u64 = 10;
const BACKLOG: usize = 128;

/// Socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketAddress {
	/// VSOCK address.
	#[cfg(feature = "vm")]
	Vsock(VsockAddr),
	/// Unix address.
	Unix(UnixAddr),
}

/// VSOCK flag for talking to host.
pub const VMADDR_FLAG_TO_HOST: u8 = 0x01;
/// Don't specify any flags for a VSOCK.
pub const VMADDR_NO_FLAGS: u8 = 0x00;

impl SocketAddress {
	/// Create a new Unix socket.
	///
	/// # Panics
	///
	/// Panics if `nix::sys::socket::UnixAddr::new` panics.
	#[must_use]
	pub fn new_unix(path: &str) -> Self {
		let addr = UnixAddr::new(path).unwrap();
		Self::Unix(addr)
	}

	/// Create a new Vsock socket.
	///
	/// For flags see: [Add flags field in the vsock address](<https://lkml.org/lkml/2020/12/11/249>).
	#[cfg(feature = "vm")]
	#[allow(unsafe_code)]
	pub fn new_vsock(cid: u32, port: u32, flags: u8) -> Self {
		#[repr(C)]
		struct sockaddr_vm {
			svm_family: libc::sa_family_t,
			svm_reserved1: libc::c_ushort,
			svm_port: libc::c_uint,
			svm_cid: libc::c_uint,
			// Field added [here](https://github.com/torvalds/linux/commit/3a9c049a81f6bd7c78436d7f85f8a7b97b0821e6)
			// but not yet in a version of libc we can use.
			svm_flags: u8,
			svm_zero: [u8; 3],
		}

		let vsock_addr = sockaddr_vm {
			svm_family: AddressFamily::Vsock as libc::sa_family_t,
			svm_reserved1: 0,
			svm_cid: cid,
			svm_port: port,
			svm_flags: flags,
			svm_zero: [0; 3],
		};
		let vsock_addr_len = size_of::<sockaddr_vm>() as libc::socklen_t;
		let addr = unsafe {
			VsockAddr::from_raw(
				&vsock_addr as *const sockaddr_vm as *const libc::sockaddr,
				Some(vsock_addr_len),
			)
			.unwrap()
		};
		Self::Vsock(addr)
	}

	/// Get the `AddressFamily` of the socket.
	#[must_use]
	pub fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(_) => AddressFamily::Vsock,
			Self::Unix(_) => AddressFamily::Unix,
		}
	}

	/// Convenience method for accessing the wrapped address
	#[must_use]
	pub fn addr(&self) -> Box<dyn SockaddrLike> {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsa) => Box::new(vsa),
			Self::Unix(ua) => Box::new(ua),
		}
	}
}

/// Handle on a stream
pub struct Stream {
	fd: RawFd,
}

impl Stream {
	/// Create a new `Stream` from a `SocketAddress` and a timeout
	pub fn connect(
		addr: &SocketAddress,
		timeout: TimeVal,
	) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for _ in 0..MAX_RETRY {
			let fd = socket_fd(addr)?;
			let stream = Self { fd };

			// set `SO_RCVTIMEO`
			let receive_timeout = sockopt::ReceiveTimeout;
			receive_timeout.set(fd, &timeout)?;

			let send_timeout = sockopt::SendTimeout;
			send_timeout.set(fd, &timeout)?;

			match connect(stream.fd, &*addr.addr()) {
				Ok(()) => return Ok(stream),
				Err(e) => err = IOError::ConnectNixError(e),
			}

			std::thread::sleep(std::time::Duration::from_millis(
				BACKOFF_MILLISECONDS,
			));
		}

		Err(err)
	}

	/// Sends a buffer over the underlying socket
	pub fn send(&self, buf: &[u8]) -> Result<(), IOError> {
		let len = buf.len();
		// First, send the length of the buffer
		{
			let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();

			// First, send the length of the buffer
			let mut sent_bytes = 0;
			while sent_bytes < len_buf.len() {
				sent_bytes += match send(
					self.fd,
					&len_buf[sent_bytes..len_buf.len()],
					MsgFlags::empty(),
				) {
					Ok(size) => size,
					Err(err) => return Err(IOError::SendNixError(err)),
				};
			}
		}

		// Then, send the contents of the buffer
		{
			let mut sent_bytes = 0;
			while sent_bytes < len {
				sent_bytes += match send(
					self.fd,
					&buf[sent_bytes..len],
					MsgFlags::empty(),
				) {
					Ok(size) => size,
					Err(err) => return Err(IOError::SendNixError(err)),
				}
			}
		}

		Ok(())
	}

	/// Receive from the underlying socket
	pub fn recv(&self) -> Result<Vec<u8>, IOError> {
		let length: usize = {
			{
				let mut buf = [0u8; size_of::<u64>()];
				let len = buf.len();
				std::debug_assert!(buf.len() == 8);

				let mut received_bytes = 0;
				while received_bytes < len {
					received_bytes += match recv(
						self.fd,
						&mut buf[received_bytes..len],
						MsgFlags::empty(),
					) {
						Ok(0) => {
							return Err(IOError::RecvConnectionClosed);
						}
						Ok(size) => size,
						Err(nix::Error::EINTR) => {
							return Err(IOError::RecvInterrupted);
						}
						Err(nix::Error::EAGAIN) => {
							return Err(IOError::RecvTimeout);
						}
						Err(err) => {
							return Err(IOError::RecvNixError(err));
						}
					};
				}

				u64::from_le_bytes(buf)
					.try_into()
					// Should only be possible if we are on 32bit architecture
					.map_err(|_| IOError::ArithmeticSaturation)?
			}
		};

		// Read the buffer
		let mut buf = vec![0; length];
		{
			let mut received_bytes = 0;
			while received_bytes < length {
				received_bytes += match recv(
					self.fd,
					&mut buf[received_bytes..length],
					MsgFlags::empty(),
				) {
					Ok(0) => {
						return Err(IOError::RecvConnectionClosed);
					}
					Ok(size) => size,
					Err(nix::Error::EINTR) => {
						return Err(IOError::RecvInterrupted);
					}
					Err(nix::Error::EAGAIN) => {
						return Err(IOError::RecvTimeout);
					}
					Err(err) => {
						return Err(IOError::NixError(err));
					}
				};
			}
		}
		Ok(buf)
	}
}

impl Read for Stream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		match recv(self.fd, buf, MsgFlags::empty()) {
			Ok(0) => Err(std::io::Error::new(
				ErrorKind::ConnectionAborted,
				"read 0 bytes",
			)),
			Ok(size) => Ok(size),
			Err(err) => Err(std::io::Error::from_raw_os_error(err as i32)),
		}
	}
}

impl Write for Stream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		match send(self.fd, buf, MsgFlags::empty()) {
			Ok(0) => Err(std::io::Error::new(
				ErrorKind::ConnectionAborted,
				"wrote 0 bytes",
			)),
			Ok(size) => Ok(size),
			Err(err) => Err(std::io::Error::from_raw_os_error(err as i32)),
		}
	}

	// No-op because we can't flush a socket.
	fn flush(&mut self) -> Result<(), std::io::Error> {
		Ok(())
	}
}

impl Drop for Stream {
	fn drop(&mut self) {
		// Its ok if either of these error - likely means the other end of the
		// connection has been shutdown
		let _ = shutdown(self.fd, Shutdown::Both);
		let _ = close(self.fd);
	}
}

/// Abstraction to listen for incoming stream connections.
pub struct Listener {
	fd: RawFd,
	addr: SocketAddress,
}

impl Listener {
	/// Bind and listen on the given address.
	pub(crate) fn listen(addr: SocketAddress) -> Result<Self, IOError> {
		// In case the last connection at this addr did not shutdown correctly
		Self::clean(&addr);

		let fd = socket_fd(&addr)?;
		bind(fd, &*addr.addr())?;
		listen(fd, BACKLOG)?;

		Ok(Self { fd, addr })
	}

	fn accept(&self) -> Result<Stream, IOError> {
		let fd = accept(self.fd)?;

		Ok(Stream { fd })
	}

	/// Remove Unix socket if it exists
	fn clean(addr: &SocketAddress) {
		// Not irrefutable when "vm" is enabled
		#[allow(irrefutable_let_patterns)]
		if let SocketAddress::Unix(addr) = addr {
			if let Some(path) = addr.path() {
				if path.exists() {
					drop(std::fs::remove_file(path));
				}
			}
		}
	}
}

impl Iterator for Listener {
	type Item = Stream;
	fn next(&mut self) -> Option<Self::Item> {
		self.accept().ok()
	}
}

impl Drop for Listener {
	fn drop(&mut self) {
		// Its ok if either of these error - likely means the other end of the
		// connection has been shutdown
		let _ = shutdown(self.fd, Shutdown::Both);
		let _ = close(self.fd);
		Self::clean(&self.addr);
	}
}

fn socket_fd(addr: &SocketAddress) -> Result<RawFd, IOError> {
	socket(
		addr.family(),
		// Type - sequenced, two way byte stream. (full duplexed).
		// Stream must be in a connected state before send/receive.
		SockType::Stream,
		// Flags
		SockFlag::empty(),
		// Protocol - no protocol needs to be specified as SOCK_STREAM
		// is both a type and protocol.
		None,
	)
	.map_err(IOError::NixError)
}

#[cfg(test)]
mod test {

	use std::{
		os::{fd::AsRawFd, unix::net::UnixListener},
		path::Path,
		str::from_utf8,
		thread,
	};

	use super::*;

	fn timeval() -> TimeVal {
		TimeVal::seconds(1)
	}

	// A simple test socket server which says "PONG" when you send "PING".
	// Then it kills itself.
	pub struct HarakiriPongServer {
		path: String,
		fd: Option<i32>,
	}

	impl HarakiriPongServer {
		pub fn new(path: String) -> Self {
			Self { path, fd: None }
		}
		pub fn start(&mut self) {
			let listener = UnixListener::bind(&self.path).unwrap();
			self.fd = Some(listener.as_raw_fd());

			let (mut stream, _peer_addr) = listener.accept().unwrap();

			// Read 4 bytes ("PING")
			let mut buf = [0u8; 4];
			stream.read_exact(&mut buf).unwrap();

			// Send "PONG" if "PING" was sent
			if from_utf8(&buf).unwrap() == "PING" {
				let _ = stream.write(b"PONG").unwrap();
			}
		}
	}

	impl Drop for HarakiriPongServer {
		fn drop(&mut self) {
			if let Some(fd) = &self.fd {
				// Cleanup server fd if we have access to one
				let _ = shutdown(fd.to_owned(), Shutdown::Both);
				let _ = close(fd.to_owned());

				let server_socket = Path::new(&self.path);
				if server_socket.exists() {
					drop(std::fs::remove_file(server_socket));
				}
				println!("HarakiriPongServer dropped successfully.")
			} else {
				println!(
					"HarakiriPongServer dropped without a fd set. All done."
				)
			}
		}
	}

	#[test]
	fn stream_integration_test() {
		// Ensure concurrent tests do not listen at the same path
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./stream_integration_test.sock")
				.unwrap();
		let addr: SocketAddress = SocketAddress::Unix(unix_addr);
		let listener: Listener = Listener::listen(addr.clone()).unwrap();
		let client = Stream::connect(&addr, timeval()).unwrap();
		let server = listener.accept().unwrap();

		let data = vec![1, 2, 3, 4, 5, 6, 6, 6];
		client.send(&data).unwrap();

		let resp = server.recv().unwrap();

		assert_eq!(data, resp);
	}

	#[test]
	fn stream_implements_read_write_traits() {
		let socket_server_path = "./stream_implements_read_write_traits.sock";

		// Start a simple socket server which replies "PONG" to any incoming
		// request
		let mut server =
			HarakiriPongServer::new(socket_server_path.to_string());

		// Start the server in its own thread
		thread::spawn(move || {
			server.start();
		});

		// Now create a stream connecting to this mini-server
		let unix_addr =
			nix::sys::socket::UnixAddr::new(socket_server_path).unwrap();
		let addr = SocketAddress::Unix(unix_addr);
		let mut pong_stream = Stream::connect(&addr, timeval()).unwrap();

		// Write "PING"
		let written = pong_stream.write(b"PING").unwrap();
		assert_eq!(written, 4);

		// Read, and expect "PONG"
		let mut resp = [0u8; 4];
		let res = pong_stream.read(&mut resp).unwrap();
		assert_eq!(res, 4);
		assert_eq!(from_utf8(&resp).unwrap(), "PONG");
	}

	#[test]
	fn listener_iterator_test() {
		// Ensure concurrent tests are not attempting to listen at the same
		// address
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./listener_iterator_test.sock")
				.unwrap();
		let addr = SocketAddress::Unix(unix_addr);

		let mut listener = Listener::listen(addr.clone()).unwrap();

		let handler = std::thread::spawn(move || {
			if let Some(stream) = listener.next() {
				let req = stream.recv().unwrap();
				stream.send(&req).unwrap();
			}
		});

		let client = Stream::connect(&addr, timeval()).unwrap();

		let data = vec![1, 2, 3, 4, 5, 6, 6, 6];
		client.send(&data).unwrap();
		let resp = client.recv().unwrap();
		assert_eq!(data, resp);

		handler.join().unwrap();
	}
}
