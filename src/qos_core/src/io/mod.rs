//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod stream;

pub use stream::{
	Listener, SocketAddress, Stream, TimeVal, TimeValLike, VMADDR_FLAG_TO_HOST,
	VMADDR_NO_FLAGS,
};

/// QOS I/O error
#[derive(Debug)]
pub enum IOError {
	/// `nix::Error` wrapper.
	NixError(nix::Error),
	/// Arithmetic operation saturated.
	ArithmeticSaturation,
	/// Unknown error.
	UnknownError,
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
