#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

use std::os::unix::io::{RawFd};
use std::mem::size_of;
use nix::{
	sys::socket::{
		bind, connect, accept, listen, shutdown, socket, recv, AddressFamily,
		Shutdown, SockFlag, SockType, SockaddrLike, MsgFlags, send
	},
	unistd::close,
};

use super::IOError;

#[cfg(feature="vm")]
use nix::sys::socket::VsockAddr;

#[cfg(feature = "local")]
use nix::sys::socket::UnixAddr;

// TODO: mutual exclusive compilation local/vm compile time check

const MAX_RETRY: usize = 8;
const BACKLOG: usize = 128;

struct Stream { fd: RawFd }

impl Stream {
	fn connect(addr: &dyn SockaddrLike) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for i in 0..MAX_RETRY {
			let fd = socket_fd(addr)?;
			let stream = Self { fd };

      // TODO: Revisit these options
			// setsockopt(vsock.as_raw_fd(), sockopt::ReuseAddr, &true)?;
			// setsockopt(vsock.as_raw_fd(), sockopt::ReusePort, &true)?;

			match connect(stream.fd, addr) {
				Ok(_) => return Ok(stream),
				Err(e) => err = IOError::NixError(e),
			}

			// Exponentially back off before reattempting connection
			std::thread::sleep(std::time::Duration::from_secs(1 << i));
		}

		Err(err)
	}

	fn send(fd: RawFd, buf: &Vec<u8>) -> Result<(), IOError>{
		let len = buf.len();

		// First, send the length of the buffer
		{
			let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();

			// First, sent the length of the buffer
			let mut sent_bytes = 0;
			while sent_bytes < len_buf.len() {
				sent_bytes += match send(
					fd,
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
				sent_bytes +=
					match send(fd, &buf[sent_bytes..len], MsgFlags::empty()) {
						Ok(size) => size,
						Err(nix::Error::EINTR) => 0,
						Err(err) => return Err(IOError::NixError(err)),
					}
			}
		}

		Ok(())
	}
  
	pub fn recv(fd: RawFd) -> Result<Vec<u8>, IOError> {
		// First, read the length
		let length: usize = {
			{
				let mut buf = [0u8; size_of::<u64>()];
				let len = buf.len();
				std::debug_assert!(buf.len() == 8);

				let mut received_bytes = 0;
				while received_bytes < len {
					received_bytes += match recv(
						fd,
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
		let mut buf = Vec::with_capacity(length);
		{
			let mut received_bytes = 0;
			while received_bytes < length {
				received_bytes += match recv(
					fd,
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

struct Listener { fd: RawFd }

impl Listener {
	/// Bind and listen on the given address.
	fn serve(addr: &dyn SockaddrLike) -> Result<Self, IOError> {
		let fd = socket_fd(addr)?;

		bind(fd, addr)?;
		listen(fd, BACKLOG)?;

		Ok(Self { fd })
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
	}
}

fn socket_fd(addr: &dyn SockaddrLike) -> Result<RawFd, IOError> {
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
