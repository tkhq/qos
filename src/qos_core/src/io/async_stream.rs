//! Abstractions to handle connection based socket streams.

use std::time::Duration;

#[cfg(feature = "vm")]
pub use nix::sys::time::TimeVal;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{UnixListener, UnixSocket, UnixStream},
};
use tokio_vsock::{VsockListener, VsockStream};

use super::{IOError, SocketAddress};

enum InnerListener {
	Unix(UnixListener),
	#[cfg(feature = "vm")]
	Vsock(VsockListener),
}

enum InnerStream {
	Unix(UnixStream),
	#[cfg(feature = "vm")]
	Vsock(VsockStream),
}

/// Handle on a stream
pub struct AsyncStream(InnerStream);

impl AsyncStream {
	fn unix_accepted(stream: UnixStream) -> Self {
		Self(InnerStream::Unix(stream))
	}

	fn vsock_accepted(stream: VsockStream) -> Self {
		Self(InnerStream::Vsock(stream))
	}

	/// Create a new `Stream` from a `SocketAddress` and a timeout and connect using async
	pub async fn connect(
		addr: &SocketAddress,
		timeout: TimeVal,
	) -> Result<AsyncStream, IOError> {
		match addr {
			SocketAddress::Unix(uaddr) => {
				let path =
					uaddr.path().ok_or(IOError::ConnectAddressInvalid)?;

				let socket = UnixSocket::new_stream()?;
				let timeout = Duration::new(
					timeout.tv_sec() as u64,
					timeout.tv_usec() as u32 * 1000,
				);

				let inner =
					tokio::time::timeout(timeout.into(), socket.connect(path))
						.await??;

				Ok(Self(InnerStream::Unix(inner)))
			}
			SocketAddress::Vsock(vaddr) => {
				let vaddr =
					tokio_vsock::VsockAddr::new(vaddr.cid(), vaddr.port());
				let inner = VsockStream::connect(vaddr).await?;

				Ok(Self(InnerStream::Vsock(inner)))
			}
		}
	}

	/// Sends a buffer over the underlying socket using async
	pub(crate) async fn send(&mut self, buf: &[u8]) -> Result<(), IOError> {
		match &mut self.0 {
			InnerStream::Unix(ref mut s) => send(s, buf).await,
			InnerStream::Vsock(ref mut s) => send(s, buf).await,
		}
	}

	/// Receive from the underlying socket using async
	pub(crate) async fn recv(&mut self) -> Result<Vec<u8>, IOError> {
		match &mut self.0 {
			InnerStream::Unix(ref mut s) => recv(s).await,
			InnerStream::Vsock(ref mut s) => recv(s).await,
		}
	}

	/// Perform a "call" by sending the req_buf bytes and waiting for reply on the same socket.
	pub async fn call(&mut self, req_buf: &[u8]) -> Result<Vec<u8>, IOError> {
		self.send(req_buf).await?;
		self.recv().await
	}
}

async fn send<S: AsyncWriteExt + Unpin>(
	stream: &mut S,
	buf: &[u8],
) -> Result<(), IOError> {
	let len = buf.len();
	// First, send the length of the buffer
	let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();
	stream.write_all(&len_buf).await?;
	// Send the actual contents of the buffer
	stream.write_all(buf).await?;

	Ok(())
}

async fn recv<S: AsyncReadExt + Unpin>(
	stream: &mut S,
) -> Result<Vec<u8>, IOError> {
	let length: usize = {
		let mut buf = [0u8; size_of::<u64>()];
		stream.read_exact(&mut buf).await?;
		u64::from_le_bytes(buf)
			.try_into()
			// Should only be possible if we are on 32bit architecture
			.map_err(|_| IOError::ArithmeticSaturation)?
	};

	// Read the buffer
	let mut buf = vec![0; length];
	stream.read_exact(&mut buf).await?;

	Ok(buf)
}

/// Abstraction to listen for incoming stream connections.
pub struct AsyncListener {
	inner: InnerListener,
	// addr: SocketAddress,
}

impl AsyncListener {
	/// Bind and listen on the given address.
	pub(crate) async fn listen(addr: SocketAddress) -> Result<Self, IOError> {
		let listener = match addr {
			SocketAddress::Unix(uaddr) => {
				let path =
					uaddr.path().ok_or(IOError::ConnectAddressInvalid)?;
				let inner = InnerListener::Unix(UnixListener::bind(path)?);
				Self { inner }
			}
			SocketAddress::Vsock(vaddr) => {
				let vaddr =
					tokio_vsock::VsockAddr::new(vaddr.cid(), vaddr.port());
				let inner = InnerListener::Vsock(VsockListener::bind(vaddr)?);
				Self { inner }
			}
		};

		Ok(listener)
	}

	/// Accept a new connection.
	pub async fn accept(&self) -> Result<AsyncStream, IOError> {
		let stream = match &self.inner {
			InnerListener::Unix(l) => {
				let (s, _) = l.accept().await?;
				AsyncStream::unix_accepted(s)
			}
			InnerListener::Vsock(l) => {
				let (s, _) = l.accept().await?;
				AsyncStream::vsock_accepted(s)
			}
		};

		Ok(stream)
	}
}
