//! Core components of QOS.
//!
//! Any code that runs in the enclave should be contained here.
//!
//! This crate should have as minimal dependencies as possible to decrease
//! supply chain attack vectors and audit burden.
//! TODO: high level docs explaining QOS, including key terms
//! Route specific docs should go on protocol message
//! # Quorum OS
//!
//! ## Overview
//!
//! ## Key Terms
//!
//! ### Quorum Key
//!
//! ### Quorum Member
//!
//! ### Personal Key
//!
//! ### Setup Key
//!
//! ### Manifest
//!
//! ### Namespace
//!
//! ### Secure App
//!
//! ### Enclave

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

// "vm" is necessary for production and we don't want any mock data slipping in.
#[cfg(all(feature = "vm", feature = "mock"))]
compile_error!(
	"feature \"vm\" and feature \"mock\" cannot be enabled at the same time"
);

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use borsh::BorshSerialize;
use borsh::BorshDeserialize;
use qos_crypto::RsaPair;

use crate::protocol::{services::boot::Manifest, ProtocolError};

pub mod cli;
pub mod client;
pub mod coordinator;
pub mod hex;
pub mod io;
pub mod parser;
pub mod protocol;
pub mod server;

/// Path to Quorum Key secret.
#[cfg(not(feature = "vm"))]
pub const SECRET_FILE: &str = "./qos.quorum.key";
/// Path to Quorum Key secret.
#[cfg(feature = "vm")]
pub const SECRET_FILE: &str = "/qos.quorum.key";

/// Path to Pivot binary.
#[cfg(not(feature = "vm"))]
pub const PIVOT_FILE: &str = "../target/debug/pivot_ok";
/// Path to Pivot binary.
#[cfg(feature = "vm")]
pub const PIVOT_FILE: &str = "/qos.pivot.bin";

/// Path to Ephemeral Key.
#[cfg(not(feature = "vm"))]
pub const EPHEMERAL_KEY_FILE: &str = "./qos.ephemeral.key";
/// Path to Ephemeral Key.
#[cfg(feature = "vm")]
pub const EPHEMERAL_KEY_FILE: &str = "/qos.ephemeral.key";

/// Handles for read only state accessible to all of QOS.
///
/// All data here should be put once at some point in the boot flow, and then
/// only ever read after that.
struct Handles {
	/// Path to file containing the PEM encoded Ephemeral Key.
	ephemeral: String,
	/// Path to file containing the PEM encoded Quorum Key.
	quorum: String,
	/// Path to the file container the Borsh encoded manifest
	manifest: String,
	/// Path to the file containing the pivot
	pivot: String,
}

impl Handles {
	/// Get the Ephemeral Key pair.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral Key has not been put.
	fn get_ephemeral_key(&self) -> Result<RsaPair, ProtocolError> {
		let pair = RsaPair::from_pem_file(&self.ephemeral)?;
		Ok(pair)
	}

	/// Put the Ephemeral Key pair.
	///
	/// # Errors
	///
	/// Errors if the Ephemeral Key has already been put.
	fn put_ephemeral_key(&self, pair: &RsaPair) -> Result<(), ProtocolError> {
		Self::write_as_read_only(&self.ephemeral, &pair.private_key_to_pem()?)
	}

	/// Put the Quorum Key pair.
	///
	/// # Errors
	///
	/// Errors if the Quorum Key has already been put.
	fn get_quorum_key(&self) -> Result<RsaPair, ProtocolError> {
		let pair = RsaPair::from_pem_file(&self.quorum)?;
		Ok(pair)
	}

	/// Put the Quorum Key pair.
	///
	/// # Errors
	///
	/// Errors if the Quorum Key has already been put.
	fn put_quorum_key(&self, pair: &RsaPair) -> Result<(), ProtocolError> {
		Self::write_as_read_only(&self.quorum, &pair.private_key_to_pem()?)
	}

	/// Get the Manifest.
	///
	/// # Errors
	///
	/// Errors if the Manifest has not been put.
	fn get_manifest(&self) -> Result<Manifest, ProtocolError> {
		let manifest = Manifest::try_from_slice(&fs::read(&self.manifest)?)?;
		Ok(manifest)
	}

	/// Put the Manifest.
	///
	/// # Errors
	///
	/// Errors if the Manifest has already been put.
	fn put_manifest(&self, manifest: &Manifest) -> Result<(), ProtocolError> {
		Self::write_as_read_only(&self.manifest, &manifest.try_to_vec()?)
	}

	/// Get the path to the Pivot binary.
	fn get_pivot_path(&self) -> String {
		self.pivot.clone()
	}

	/// Put the Pivot binary, ensuring it is an executable.
	fn put_pivot(&self, pivot: &[u8]) -> Result<(), ProtocolError> {
		if Path::new(&self.pivot).exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		fs::write(&self.pivot, pivot)?;
		fs::set_permissions(
			&self.pivot,
			std::fs::Permissions::from_mode(0o111),
		)?;
		Ok(())
	}

	/// Helper function for ready only writes.
	fn write_as_read_only<P: AsRef<Path>>(
		path: P,
		buf: &[u8],
	) -> Result<(), ProtocolError> {
		if path.as_ref().exists() {
			Err(ProtocolError::CannotModifyPostPivotStatic)?;
		}

		fs::write(&path, buf)?;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
		Ok(())
	}
}
