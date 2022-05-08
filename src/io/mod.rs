//! Interaction with any sys calls should be contained within this module.

pub(crate) mod stream;

#[derive(Debug)]
pub enum IOError {
	NixError(nix::Error),
	ArithmeticSaturation,
	UnsupportedAddr,
	UnknownError,
}

impl From<nix::Error> for IOError {
	fn from(err: nix::Error) -> Self {
		Self::NixError(err)
	}
}