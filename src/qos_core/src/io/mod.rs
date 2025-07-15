//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod async_pool;
mod async_stream;
pub use async_pool::*;
pub use async_stream::*;

mod stream;
pub use stream::{SocketAddress, VMADDR_FLAG_TO_HOST, VMADDR_NO_FLAGS};

pub use nix::sys::time::{TimeVal, TimeValLike};

/// QOS I/O error
#[derive(Debug)]
pub enum IOError {
	/// `std::io::Error` wrapper.
	StdIoError(std::io::Error),
	/// `nix::Error` wrapper.
	NixError(nix::Error),
	/// Arithmetic operation saturated.
	ArithmeticSaturation,
	/// Unknown error.
	UnknownError,
	/// Stream was not connected when expected to be connected.
	DisconnectedStream,
	/// Connect address invalid
	ConnectAddressInvalid,
	/// Timed out while claling `connect` over a socket.
	ConnectTimeout,
	/// Timed out while calling `recv` over a socket.
	RecvTimeout,
	/// The `recv` system call was interrupted while receiving over a socket.
	RecvInterrupted,
	/// Receive was called on a closed connection.
	RecvConnectionClosed,
	/// Client could not connect at the given socket address.
	ConnectNixError(nix::Error),
	/// A nix error encountered while calling `send`.
	SendNixError(nix::Error),
	/// A nix error encountered while calling `recv`.
	RecvNixError(nix::Error),
	/// Reading the response size resulted in a size which exceeds the max payload size.
	OversizedPayload(usize),
	/// A async socket pool error during pool operations.
	PoolError(PoolError),
}

impl From<nix::Error> for IOError {
	fn from(err: nix::Error) -> Self {
		Self::NixError(err)
	}
}

impl From<std::io::Error> for IOError {
	fn from(err: std::io::Error) -> Self {
		Self::StdIoError(err)
	}
}

impl From<PoolError> for IOError {
	fn from(value: PoolError) -> Self {
		Self::PoolError(value)
	}
}
