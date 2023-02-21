//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod stream;

pub use stream::SocketAddress;
pub(crate) use stream::{Listener, Stream};

/// QOS I/O error
#[derive(Debug)]
pub enum IOError {
	/// `nix::Error` wrapper.
	NixError(nix::Error),
	/// Arithmetic operation saturated.
	ArithmeticSaturation,
	/// Unknown error.
	UnknownError,
	/// Timed out while waiting for a response.
	Timeout,
	/// An internal channel disconnected - this is a bug.
	InternalChannelDisconnect,
}

impl From<nix::Error> for IOError {
	fn from(err: nix::Error) -> Self {
		Self::NixError(err)
	}
}
