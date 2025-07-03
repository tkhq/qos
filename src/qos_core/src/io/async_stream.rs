//! Abstractions to handle connection based socket streams.

use std::{
	pin::Pin,
	time::{Duration, SystemTime},
};

pub use nix::sys::time::TimeVal;

use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	net::{UnixListener, UnixSocket, UnixStream},
};
#[cfg(feature = "vm")]
use tokio_vsock::{VsockListener, VsockStream};

use super::{IOError, SocketAddress};

#[derive(Debug)]
enum InnerListener {
	Unix(UnixListener),
	#[cfg(feature = "vm")]
	Vsock(VsockListener),
}

#[derive(Debug)]
enum InnerStream {
	Unix(UnixStream),
	#[cfg(feature = "vm")]
	Vsock(VsockStream),
}

/// Handle on a stream
#[derive(Debug)]
pub struct AsyncStream {
	address: Option<SocketAddress>,
	inner: Option<InnerStream>,
	timeout: Duration,
}

impl AsyncStream {
	// accept a new connection, used by server side
	fn unix_accepted(stream: UnixStream) -> Self {
		Self {
			address: None,
			inner: Some(InnerStream::Unix(stream)),
			timeout: Duration::ZERO,
		}
	}

	// accept a new connection, used by server side
	#[cfg(feature = "vm")]
	fn vsock_accepted(stream: VsockStream) -> Self {
		Self {
			address: None,
			inner: Some(InnerStream::Vsock(stream)),
			timeout: Duration::ZERO,
		}
	}

	/// Create a new `AsyncStream` with known `SocketAddress` and `TimeVal`. The stream starts disconnected
	/// and will connect on the first `call`.
	#[must_use]
	pub fn new(address: &SocketAddress, timeout: TimeVal) -> Self {
		#[allow(clippy::cast_possible_truncation)]
		#[allow(clippy::cast_sign_loss)]
		let timeout = Duration::new(
			timeout.tv_sec() as u64,
			timeout.tv_usec() as u32 * 1000,
		);

		Self { address: Some(address.clone()), inner: None, timeout }
	}

	/// Create a new `Stream` from a `SocketAddress` and a timeout and connect using async
	/// Sets `inner` to the new stream.
	pub async fn connect(&mut self) -> Result<(), IOError> {
		let timeout = self.timeout;
		let addr = self.address()?.clone();

		match self.address()? {
			SocketAddress::Unix(_uaddr) => {
				let inner = retry_unix_connect(addr, timeout).await?;

				self.inner = Some(InnerStream::Unix(inner));
			}
			#[cfg(feature = "vm")]
			SocketAddress::Vsock(_vaddr) => {
				let inner = retry_vsock_connect(addr, timeout).await?;

				self.inner = Some(InnerStream::Vsock(inner));
			}
		}

		Ok(())
	}

	/// Reconnects this `AsyncStream` by calling `connect` again on the underlaying socket
	pub async fn reconnect(&mut self) -> Result<(), IOError> {
		let timeout = self.timeout;
		let addr = self.address()?.clone();

		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => {
				*s = retry_unix_connect(addr, timeout).await?;
			}
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => {
				*s = retry_vsock_connect(addr, timeout).await?;
			}
		}
		Ok(())
	}

	/// Sends a buffer over the underlying socket using async
	pub async fn send(&mut self, buf: &[u8]) -> Result<(), IOError> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => send(s, buf).await,
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => send(s, buf).await,
		}
	}

	/// Receive from the underlying socket using async
	pub async fn recv(&mut self) -> Result<Vec<u8>, IOError> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => recv(s).await,
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => recv(s).await,
		}
	}

	/// Perform a "call" by sending the `req_buf` bytes and waiting for reply on the same socket.
	pub async fn call(&mut self, req_buf: &[u8]) -> Result<Vec<u8>, IOError> {
		// first time? connect
		if self.inner.is_none() {
			self.connect().await?;
		}
		self.send(req_buf).await?;
		self.recv().await
	}

	fn address(&self) -> Result<&SocketAddress, IOError> {
		self.address.as_ref().ok_or(IOError::ConnectAddressInvalid)
	}

	fn inner_mut(&mut self) -> Result<&mut InnerStream, IOError> {
		self.inner.as_mut().ok_or(IOError::DisconnectedStream)
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

impl From<IOError> for std::io::Error {
	fn from(value: IOError) -> Self {
		match value {
			IOError::DisconnectedStream => std::io::Error::new(
				std::io::ErrorKind::NotFound,
				"connection not found",
			),
			_ => {
				std::io::Error::new(std::io::ErrorKind::Other, "unknown error")
			}
		}
	}
}

impl AsyncRead for AsyncStream {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => Pin::new(s).poll_read(cx, buf),
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => Pin::new(s).poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for AsyncStream {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, std::io::Error>> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => Pin::new(s).poll_write(cx, buf),
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => Pin::new(s).poll_write(cx, buf),
		}
	}

	fn poll_flush(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => Pin::new(s).poll_flush(cx),
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => Pin::new(s).poll_flush(cx),
		}
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => Pin::new(s).poll_shutdown(cx),
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => Pin::new(s).poll_shutdown(cx),
		}
	}
}

/// Abstraction to listen for incoming stream connections.
pub struct AsyncListener {
	inner: InnerListener,
	// addr: SocketAddress,
}

impl AsyncListener {
	/// Bind and listen on the given address.
	pub(crate) fn listen(addr: &SocketAddress) -> Result<Self, IOError> {
		let listener = match *addr {
			SocketAddress::Unix(uaddr) => {
				let path =
					uaddr.path().ok_or(IOError::ConnectAddressInvalid)?;
				let inner = InnerListener::Unix(UnixListener::bind(path)?);
				Self { inner }
			}
			#[cfg(feature = "vm")]
			SocketAddress::Vsock(vaddr) => {
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
			#[cfg(feature = "vm")]
			InnerListener::Vsock(l) => {
				let (s, _) = l.accept().await?;
				AsyncStream::vsock_accepted(s)
			}
		};

		Ok(stream)
	}
}

impl Drop for AsyncListener {
	fn drop(&mut self) {
		match &mut self.inner {
			InnerListener::Unix(usock) => match usock.local_addr() {
				Ok(addr) => {
					if let Some(path) = addr.as_pathname() {
						_ = std::fs::remove_file(path);
					} else {
						eprintln!("unable to path the usock"); // do not crash in Drop
					}
				}
				Err(e) => eprintln!("{e}"), // do not crash in Drop
			},
			#[cfg(feature = "vm")]
			InnerListener::Vsock(_vsock) => {} // vsock's drop will clear this
		}
	}
}

// raw unix socket connect retry with timeout, 50ms period
async fn retry_unix_connect(
	addr: SocketAddress,
	timeout: Duration,
) -> Result<UnixStream, std::io::Error> {
	let sleep_time = Duration::from_millis(50);
	let eot = SystemTime::now() + timeout;
	let addr = addr.usock();
	let path = addr.path().ok_or(IOError::ConnectAddressInvalid)?;

	loop {
		let socket = UnixSocket::new_stream()?;

		eprintln!("Attempting USOCK connect to: {:?}", addr.path());
		let tr = tokio::time::timeout(timeout, socket.connect(path)).await;
		match tr {
			Ok(r) => match r {
				Ok(stream) => {
					eprintln!("Connected to USOCK at: {:?}", addr.path());
					return Ok(stream);
				}
				Err(err) => {
					eprintln!("Error connecting to USOCK: {err}");
					if SystemTime::now() > eot {
						return Err(err);
					}
					tokio::time::sleep(sleep_time).await;
				}
			},
			Err(err) => {
				eprintln!(
					"Connecting to USOCK failed with timeout error: {err}"
				);
				return Err(err.into());
			}
		}
	}
}

// raw vsock socket connect retry with timeout, 50ms period
#[cfg(feature = "vm")]
async fn retry_vsock_connect(
	addr: SocketAddress,
	timeout: Duration,
) -> Result<VsockStream, std::io::Error> {
	let sleep_time = Duration::from_millis(50);
	let eot = SystemTime::now() + timeout;
	let addr = addr.vsock();

	loop {
		eprintln!("Attempting VSOCK connect to: {:?}", addr);
		let tr =
			tokio::time::timeout(timeout, VsockStream::connect(*addr)).await;
		match tr {
			Ok(r) => match r {
				Ok(stream) => {
					eprintln!("Connected to VSOCK at: {:?}", addr);
					return Ok(stream);
				}
				Err(err) => {
					eprintln!("Error connecting to VSOCK: {}", err);
					if SystemTime::now() > eot {
						return Err(err);
					}
					tokio::time::sleep(sleep_time).await;
				}
			},
			Err(err) => {
				eprintln!(
					"Connecting to VSOCK failed with timeout error: {err}"
				);
				return Err(err.into());
			}
		}
	}
}
