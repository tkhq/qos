//! Stream

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

use nix::{
	sys::socket::{
		accept, bind, connect, listen, recv, send, shutdown, socket,
		AddressFamily, MsgFlags, Shutdown, SockAddr, SockFlag, SockType,
		SockaddrLike,
	},
	unistd::close,
};
use std::fs::remove_file;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::path::Path;

use super::IOError;

#[cfg(feature = "vm")]
use nix::sys::socket::VsockAddr;

#[cfg(feature = "local")]
use nix::sys::socket::UnixAddr;

#[derive(Clone)]
enum SocketAddr {
	#[cfg(feature = "vm")]
	Vsock(VsockAddr),
	#[cfg(feature = "local")]
	Unix(UnixAddr),
}

impl SocketAddr {
	fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(_) => AddressFamily::Vsock,
			#[cfg(feature = "local")]
			Self::Unix(_) => AddressFamily::Unix,
			_ => {
				panic!("Unknown socket addr")
			}
		}
	}

	// Convenience method for accessing the wrapped address
	fn addr(&self) -> impl SockaddrLike {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsa) => return vsa,
			#[cfg(feature = "local")]
			Self::Unix(ua) => return ua,
			_ => {
				panic!("Unknown socket addr")
			}
		}
	}
}

// TODO: mutual exclusive compilation local/vm compile time check

const MAX_RETRY: usize = 8;
const BACKLOG: usize = 128;

struct Stream {
	fd: RawFd,
}

impl Stream {
	fn connect(addr: &SocketAddr) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for i in 0..MAX_RETRY {
			let fd = socket_fd(addr)?;
			let stream = Self { fd };

			// TODO: Revisit these options
			// setsockopt(vsock.as_raw_fd(), sockopt::ReuseAddr, &true)?;
			// setsockopt(vsock.as_raw_fd(), sockopt::ReusePort, &true)?;

			match connect(stream.fd, &addr.addr()) {
				Ok(_) => return Ok(stream),
				Err(e) => err = IOError::NixError(e),
			}

			// Exponentially back off before reattempting connection
			std::thread::sleep(std::time::Duration::from_secs(1 << i));
		}

		Err(err)
	}

	fn send(&self, buf: &Vec<u8>) -> Result<(), IOError> {
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

	pub fn recv(&self) -> Result<Vec<u8>, IOError> {
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
						// Not necessarily actually an error, just the syscall was
						// interrupted while in progress.
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
		shutdown(self.fd, Shutdown::Both).unwrap_or_else(|e| {
			eprintln!("Failed to shutdown socket: {:?}", e)
		});
		close(self.fd)
			.unwrap_or_else(|e| eprintln!("Failed to close socket: {:?}", e));
	}
}

struct Listener {
	fd: RawFd,
	addr: SocketAddr,
}

impl Listener {
	/// Bind and listen on the given address.
	fn serve(addr: SocketAddr) -> Result<Self, IOError> {
		let fd = socket_fd(&addr)?;

		bind(fd, &addr.addr())?;
		listen(fd, BACKLOG)?;

		Ok(Self { fd, addr })
	}

	fn accept(&self) -> Result<Stream, IOError> {
		let fd = accept(self.fd)?;

		Ok(Stream { fd })
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
		shutdown(self.fd, Shutdown::Both).unwrap_or_else(|e| {
			eprintln!("Failed to shutdown socket: {:?}", e)
		});
		close(self.fd)
			.unwrap_or_else(|e| eprintln!("Failed to close socket: {:?}", e));

		#[cfg(feature = "local")]
		{
			if let SocketAddr::Unix(addr) = self.addr {
				if let Some(path) = addr.path() {
					if path.exists() {
						remove_file(path);
					}
				}
			}
		}
	}
}

fn socket_fd(addr: &SocketAddr) -> Result<RawFd, IOError> {
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
	.map_err(|e| IOError::NixError(e))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn stream_integration_test() {
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./test.socket").unwrap();
		let addr = SocketAddr::Unix(unix_addr);
		let listener = Listener::serve(addr.clone()).unwrap();
		let client = Stream::connect(&addr).unwrap();
		let server = listener.accept().unwrap();

		let data = vec![1, 2, 3, 4, 5, 6, 6, 6];
		client.send(&data);

		let resp = server.recv().unwrap();

		assert_eq!(data, resp);
	}
}
