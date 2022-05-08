//! Interaction with any sys calls should be contained within this module.

pub(crate) mod raw_fd;
pub(crate) mod stream_endpoint;

#[derive(Debug)]
pub enum IOError {
	NixError(nix::Error),
	ArithmeticSaturation,
	UnsupportedAddr,
	UnknownError,
}
