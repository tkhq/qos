//! Abstractions to handle connection based socket streams.

use std::{io::ErrorKind, pin::Pin};

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
pub struct Stream {
	address: Option<SocketAddress>,
	inner: Option<InnerStream>,
}

impl Stream {
	// accept a new connection, used by server side
	fn unix_accepted(stream: UnixStream) -> Self {
		Self { address: None, inner: Some(InnerStream::Unix(stream)) }
	}

	// accept a new connection, used by server side
	#[cfg(feature = "vm")]
	fn vsock_accepted(stream: VsockStream) -> Self {
		Self { address: None, inner: Some(InnerStream::Vsock(stream)) }
	}

	/// Create a new `Stream` with known `SocketAddress`. The stream starts disconnected
	/// and will connect on the first `call`.
	#[must_use]
	pub fn new(address: &SocketAddress) -> Self {
		Self { address: Some(address.clone()), inner: None }
	}

	/// Create a new `Stream` from a `SocketAddress` and a timeout and connect using async
	/// Sets `inner` to the new stream.
	pub async fn connect(&mut self) -> Result<(), IOError> {
		let addr = self.address()?;

		match self.address()? {
			SocketAddress::Unix(_uaddr) => {
				let inner = unix_connect(addr).await?;

				self.inner = Some(InnerStream::Unix(inner));
			}
			#[cfg(feature = "vm")]
			SocketAddress::Vsock(_vaddr) => {
				let inner = vsock_connect(&addr).await?;

				self.inner = Some(InnerStream::Vsock(inner));
			}
		}

		Ok(())
	}

	/// Reconnects this `Stream` by calling `connect` again on the underlaying socket
	pub async fn reconnect(&mut self) -> Result<(), IOError> {
		let addr = self.address()?.clone();

		match &mut self.inner_mut()? {
			InnerStream::Unix(ref mut s) => {
				*s = unix_connect(&addr).await?;
			}
			#[cfg(feature = "vm")]
			InnerStream::Vsock(ref mut s) => {
				*s = vsock_connect(&addr).await?;
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
		} else {
			eprintln!("SocketStream already connected, call proceeding");
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

	/// Resets the inner stream, forcing a re-connect next `call`
	pub fn reset(&mut self) {
		self.inner = None;
	}

	/// Checks if we're in `connected` state.
	/// NOTE: this does NOT mean that the connection is currently OK. It just means we've
	/// connected in the past, and our `inner` field is active.
	pub fn is_connected(&self) -> bool {
		self.inner.is_some()
	}
}

async fn send<S: AsyncWriteExt + Unpin>(
	stream: &mut S,
	buf: &[u8],
) -> Result<(), IOError> {
	let len = buf.len();
	// First, send the length of the buffer
	let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();

	// send the header
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

		stream.read_exact(&mut buf).await.map_err(|e| match e.kind() {
			ErrorKind::UnexpectedEof => IOError::RecvConnectionClosed,
			_ => IOError::StdIoError(e),
		})?;

		u64::from_le_bytes(buf)
			.try_into()
			// Should only be possible if we are on 32bit architecture
			.map_err(|_| IOError::ArithmeticSaturation)?
	};

	// Read the buffer
	let mut buf = vec![0; length];
	stream.read_exact(&mut buf).await.map_err(|e| match e.kind() {
		ErrorKind::UnexpectedEof => IOError::RecvConnectionClosed,
		_ => IOError::StdIoError(e),
	})?;

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

impl AsyncRead for Stream {
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

impl AsyncWrite for Stream {
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
pub struct Listener {
	inner: InnerListener,
}

impl Listener {
	/// Bind and listen on the given address.
	pub(crate) fn listen(addr: &SocketAddress) -> Result<Self, IOError> {
		let listener = match *addr {
			SocketAddress::Unix(uaddr) => {
				let path =
					uaddr.path().ok_or(IOError::ConnectAddressInvalid)?;
				if path.exists() {
					// attempt cleanup, this mostly happens from tests/panics
					_ = std::fs::remove_file(path);
				}
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
	pub async fn accept(&self) -> Result<Stream, IOError> {
		let stream = match &self.inner {
			InnerListener::Unix(l) => {
				let (s, _) = l.accept().await?;
				Stream::unix_accepted(s)
			}
			#[cfg(feature = "vm")]
			InnerListener::Vsock(l) => {
				let (s, _) = l.accept().await?;
				Stream::vsock_accepted(s)
			}
		};

		Ok(stream)
	}
}

impl Drop for Listener {
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

async fn unix_connect(
	addr: &SocketAddress,
) -> Result<UnixStream, std::io::Error> {
	let addr = addr.usock();
	let path = addr.path().ok_or(IOError::ConnectAddressInvalid)?;

	let socket = UnixSocket::new_stream()?;
	socket.connect(path).await
}

// raw vsock socket connect
#[cfg(feature = "vm")]
async fn vsock_connect(
	addr: &SocketAddress,
) -> Result<VsockStream, std::io::Error> {
	let addr = addr.vsock();
	VsockStream::connect(*addr).await
}
