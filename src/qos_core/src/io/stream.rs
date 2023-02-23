//! Abstractions to handle connection based socket streams.

use std::{mem::size_of, os::unix::io::RawFd, time::Instant};

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

const MAX_RETRY: usize = 8;
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
	#[cfg(feature = "vm")]
	pub fn new_vsock(cid: u32, port: u32) -> Self {
		let addr = VsockAddr::new(cid, port);
		Self::Vsock(addr)
	}

	/// Get the `AddressFamily` of the socket.
	fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(_) => AddressFamily::Vsock,
			Self::Unix(_) => AddressFamily::Unix,
		}
	}

	// Convenience method for accessing the wrapped address
	fn addr(&self) -> Box<dyn SockaddrLike> {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsa) => Box::new(vsa),
			Self::Unix(ua) => Box::new(ua),
		}
	}
}

/// Handle on a stream
// #[derive(Clone)]
pub(crate) struct Stream {
	fd: RawFd,
}

impl Stream {
	pub(crate) fn connect(
		addr: &SocketAddress,
		timeout: TimeVal,
	) -> Result<Self, IOError> {
		let mut err = IOError::UnknownError;

		for i in 0..MAX_RETRY {
			let fd = socket_fd(addr)?;
			let stream = Self { fd };

			// set `SO_RCVTIMEO`
			let receive_timeout = sockopt::ReceiveTimeout;
			receive_timeout.set(fd, &timeout)?;

			match connect(stream.fd, &*addr.addr()) {
				Ok(_) => return Ok(stream),
				Err(e) => err = IOError::SendNixError(e),
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
					Err(err) => return Err(IOError::NixError(err)),
				}
			}
		}

		Ok(())
	}

	pub(crate) fn recv(&self, timeout: TimeVal) -> Result<Vec<u8>, IOError> {
		let start = Instant::now();

		// First, check if the connection is open by using MSG_PEEK and making sure read length
		// is at least 1
		{
			let mut buf = [0u8; 1];
			loop {
				match recv(
				self.fd,
					&mut buf[..],
					MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
				) {
					Ok(read) => {
						if read == 0 {
							return Err(IOError::RecvConnectionClosed);
						};
						break
					}
					Err(nix::Error::EAGAIN) => {
						// Since we use the "MSG_DONTWAIT" flag, the call to recv is non blocking
						// and we need to manually check for a timeout
						if start.elapsed().as_millis() >= timeout.num_milliseconds() as u128 {
							return Err(IOError::RecvTimeout);
						};
					}
					Err(nix::Error::EBADF) => {
						return Err(IOError::RecvConnectionClosed);
					}
					Err(err) => {
						return Err(IOError::RecvNixError(err));
					}
				}
			}
		}

		// Second, read the length. Note we omit the MSG_PEEK flag so the cursor now moves forward
		// each read.
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
						MsgFlags::MSG_DONTWAIT,
					) {
						Ok(size) => size,
						Err(nix::Error::EINTR) => {
							return Err(IOError::RecvInterrupted);
						}
						Err(nix::Error::EAGAIN) => {
							// Since we use the "MSG_DONTWAIT" flag, the call to recv is non blocking
							// and we need to manually check for a timeout
							if start.elapsed().as_millis() >= timeout.num_milliseconds() as u128 {
								return Err(IOError::RecvTimeout);
							};
							0
						}
						Err(nix::Error::EBADF) => {
							return Err(IOError::RecvConnectionClosed);
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

		// Third, read the buffer
		let mut buf = vec![0; length];
		{
			let mut received_bytes = 0;
			while received_bytes < length {
				let size = match recv(
					self.fd,
					&mut buf[received_bytes..length],
					MsgFlags::MSG_DONTWAIT,
				) {
					Ok(size) => {
						size
					}
					Err(nix::Error::EINTR) => {
						return Err(IOError::RecvInterrupted);
					}
					Err(nix::Error::EAGAIN) => {
						if start.elapsed().as_millis() >= timeout.num_microseconds() as u128 {
							return Err(IOError::RecvTimeout);
						};
						0
					}
					Err(nix::Error::EBADF) => {
						return Err(IOError::RecvConnectionClosed);
					}
					Err(err) => {
						return Err(IOError::NixError(err));
					}
				};
				received_bytes += size;
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

	fn timeval() -> TimeVal {
		TimeVal::seconds(1)
	}

	#[test]
	fn stream_integration_test() {
		// Ensure concurrent tests are not attempting to listen at the same
		// address
		let unix_addr =
			nix::sys::socket::UnixAddr::new("./stream_integration_test.sock")
				.unwrap();
		let addr = SocketAddress::Unix(unix_addr);
		let listener = Listener::listen(addr.clone()).unwrap();
		let client = Stream::connect(&addr, timeval()).unwrap();
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
