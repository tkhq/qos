//! Interaction with any sys calls should be contained within this module.

pub(crate) mod raw_fd;
pub(crate) mod vsock;

#[derive(Debug)]
pub enum IOError {
	NixError(nix::Error),
	ArithmeticSaturation,
}
