//! Typed artifacts produced and consumed by the harness.

use std::path::PathBuf;

use crate::BuildError;

/// OCI image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
	/// Create an image reference.
	pub fn new(value: impl Into<String>) -> Result<Self, BuildError> {
		let value = value.into();
		if value.trim().is_empty() {
			return Err(BuildError::EmptyImageRef);
		}
		Ok(Self(value))
	}

	/// Return the image reference string.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl std::fmt::Display for ImageRef {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

/// QEMU-bootable EIF artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eif {
	/// Path to `nitro.eif`.
	pub path: PathBuf,
	/// Optional path to PCR output for the EIF.
	pub pcrs_path: Option<PathBuf>,
}

/// Pivot binary artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pivot {
	/// Path to the pivot binary.
	pub path: PathBuf,
}

/// Local executable artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryArtifact {
	/// Path to the executable.
	pub path: PathBuf,
}
