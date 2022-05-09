//! Interaction with any sys calls should be contained within this module.

mod stream;

pub use stream::SocketAddress;
pub(crate) use stream::{Listener, Stream};

// #[cfg_attr(test, derive(Debug))]
#[derive(Debug)]
pub enum IOError {
	NixError(nix::Error),
	ArithmeticSaturation,
	UnknownError,
}

impl From<nix::Error> for IOError {
	fn from(err: nix::Error) -> Self {
		Self::NixError(err)
	}
}
