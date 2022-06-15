//! Abstractions to handle connection based socket streams.

use std::{fs::remove_file, mem::size_of, os::unix::io::RawFd};

#[cfg(feature = "local")]
use nix::sys::socket::UnixAddr;
#[cfg(feature = "vm")]
use nix::sys::socket::VsockAddr;
use nix::{
	sys::socket::{
		accept, bind, connect, listen, recv, send, shutdown, socket,
		AddressFamily, MsgFlags, Shutdown, SockFlag, SockType, SockaddrLike,
	},
	unistd::close,
};

use super::IOError;

const MAX_RETRY: usize = 8;
const BACKLOG: usize = 128;

#[derive(Clone, Debug)]
pub enum SocketAddress {
	#[cfg(feature = "vm")]
	Vsock(VsockAddr),
	#[cfg(feature = "local")]
	Unix(UnixAddr),
}

impl SocketAddress {
	pub fn new_unix(path: &str) -> Self {
		let addr = UnixAddr::new(path).unwrap();
		Self::Unix(addr)
	}

	#[cfg(feature = "vm")]
	pub fn new_vsock(cid: u32, port: u32) -> Self {
		let addr = VsockAddr::new(cid, port);
		Self::Vsock(addr)
	}

	fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(_) => AddressFamily::Vsock,
			#[cfg(feature = "local")]
			Self::Unix(_) => AddressFamily::Unix,
		}
	}

	// Convenience method for accessing the wrapped address
	fn addr(&self) -> Box<dyn SockaddrLike> {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsa) => Box::new(vsa),
			#[cfg(feature = "local")]
			Self::Unix(ua) => Box::new(ua),
		}
	}
}

pub struct Stream {
	fd: RawFd,
}

impl Stream {
	pub(crate) fn connect(addr: &SocketAddress) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for i in 0..MAX_RETRY {
			let fd = socket_fd(addr)?;
			let stream = Self { fd };

			// TODO: Revisit these options
			// setsockopt(fd, sockopt::ReuseAddr, &true)?;
			// setsockopt(fd, sockopt::ReusePort, &true)?;

			match connect(stream.fd, &*addr.addr()) {
				Ok(_) => return Ok(stream),
				Err(e) => err = IOError::NixError(e),
			}

			// Exponentially back off before reattempting connection
			std::thread::sleep(std::time::Duration::from_secs(1 << i));
		}

		Err(err)
	}

	pub(crate) fn send(&self, buf: &[u8]) -> Result<(), IOError> {
		let len = buf.len();

		// First, send the length of the buffer
		{
			let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();

			// First, sent the length of the buffer
			let mut sent_bytes = 0;
			while sent_bytes < len_buf.len() {
				sent_bytes += match send(
					self.fd,
					&len_buf[sent_bytes..len_buf.len()],
					MsgFlags::empty(),
				) {
					Ok(size) => size,
					// Err(nix::Error::EINTR) => 0,
					Err(err) => return Err(IOError::NixError(err)),
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
					Err(nix::Error::EINTR) => 0,
					Err(err) => return Err(IOError::NixError(err)),
				}
			}
		}

		Ok(())
	}

	pub(crate) fn recv(&self) -> Result<Vec<u8>, IOError> {
		// First, read the length
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
						Ok(size) => size,
						// https://stackoverflow.com/questions/1674162/how-to-handle-eintr-interrupted-system-call#1674348
						// Not necessarily actually an error, just the syscall
						// was interrupted while in progress.
						Err(nix::Error::EINTR) => 0,
						Err(err) => return Err(IOError::NixError(err)),
					};
				}

				u64::from_le_bytes(buf)
					.try_into()
					// Should only be possible if we are on 32bit architecture
					.map_err(|_| IOError::ArithmeticSaturation)?
			}
		};

		// Then, read the buffer
		let mut buf = vec![0; length];
		{
			let mut received_bytes = 0;
			while received_bytes < length {
				received_bytes += match recv(
					self.fd,
					&mut buf[received_bytes..length],
					MsgFlags::empty(),
				) {
					Ok(size) => size,
					Err(nix::Error::EINTR) => 0,
					Err(err) => return Err(IOError::NixError(err)),
				}
			}
		}

		Ok(buf)
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
pub(crate) struct Listener {
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
		#[cfg(feature = "local")]
		{
			// Not irrefutable when "vm" is enabled
			#[allow(irrefutable_let_patterns)]
			if let SocketAddress::Unix(addr) = addr {
				if let Some(path) = addr.path() {
					if path.exists() {
						let _ = remove_file(path);
					}
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
		Self::clean(&self.addr)
	}
}

fn socket_fd(addr: &SocketAddress) -> Result<RawFd, IOError> {
	socket(
		addr.family(),
		// Type - sequenced, two way byte stream. (full duplexed).
		// Stream must be in a connected state before send/recieve.
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
	use super::*;

	#[test]
	fn stream_integration_test() {
		// Ensure concurrent tests are not attempting to listen at the same
		// address
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./stream_integration_test.sock")
				.unwrap();
		let addr = SocketAddress::Unix(unix_addr);
		let listener = Listener::listen(addr.clone()).unwrap();
		let client = Stream::connect(&addr).unwrap();
		let server = listener.accept().unwrap();

		let data = vec![1, 2, 3, 4, 5, 6, 6, 6];
		client.send(&data).unwrap();

		let resp = server.recv().unwrap();

		assert_eq!(data, resp);
	}

	#[test]
	fn listener_iterator_test() {
		// Ensure concurrent tests are not attempting to listen at the same
		// address
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./listener_iterator_test.sock")
				.unwrap();
		let addr = SocketAddress::Unix(unix_addr);

		let listener = Listener::listen(addr.clone()).unwrap();

		let handler = std::thread::spawn(move || {
			for stream in listener {
				let req = stream.recv().unwrap();
				stream.send(&req).unwrap();
				break;
			}
		});

		let client = Stream::connect(&addr).unwrap();

		let data = vec![1, 2, 3, 4, 5, 6, 6, 6];
		let _ = client.send(&data).unwrap();
		let resp = client.recv().unwrap();
		assert_eq!(data, resp);

		handler.join().unwrap();
	}
}
