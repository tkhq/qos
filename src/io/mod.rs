//! Interaction with any sys calls should be contained within this module.

pub(crate) mod stream;

#[cfg_attr(test, derive(Debug))]
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
