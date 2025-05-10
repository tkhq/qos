//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod async_stream;
mod stream;

pub use stream::{
	Listener, SocketAddress, Stream, TimeVal, TimeValLike, VMADDR_FLAG_TO_HOST,
	VMADDR_NO_FLAGS,
};

pub use async_stream::*;

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

impl From<tokio::time::error::Elapsed> for IOError {
	fn from(_: tokio::time::error::Elapsed) -> Self {
		Self::ConnectTimeout
	}
}
