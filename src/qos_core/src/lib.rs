//! Core components and logic for QOS. This contains both the logic for the
//! process running in the enclave and exports for use by secure apps and QOS
//! clients
//!
//! # Maintainers Notes
//!
//! This crate should have as minimal dependencies as possible to decrease
//! supply chain attack vectors and audit burden

/// Crate version, sourced from `Cargo.toml`.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit SHA at build time, set by `build.rs`.
pub const GIT_SHA: &str = env!("GIT_SHA");

// "vm" is necessary for production and we don't want any mock data slipping in.
#[cfg(all(feature = "vm", feature = "mock"))]
compile_error!(
	"feature \"vm\" and feature \"mock\" cannot be enabled at the same time"
);

pub mod client;
pub mod server;

pub mod cli;
pub mod handles;
pub mod io;
pub mod parser;
pub mod protocol;
pub mod reaper;

/// Path to Quorum Key secret.
#[cfg(not(feature = "vm"))]
pub const QUORUM_FILE: &str = "./local-enclave/qos.quorum.key";
/// Path to Quorum Key secret.
#[cfg(feature = "vm")]
pub const QUORUM_FILE: &str = "/qos.quorum.key";

/// Path to Pivot binary.
#[cfg(not(feature = "vm"))]
pub const PIVOT_FILE: &str = "./local-enclave/qos.pivot.bin";
/// Path to Pivot binary.
#[cfg(feature = "vm")]
pub const PIVOT_FILE: &str = "/qos.pivot.bin";

/// Path to Ephemeral Key.
#[cfg(not(feature = "vm"))]
pub const EPHEMERAL_KEY_FILE: &str = "./local-enclave/qos.ephemeral.key";
/// Path to Ephemeral Key.
#[cfg(feature = "vm")]
pub const EPHEMERAL_KEY_FILE: &str = "/qos.ephemeral.key";

/// Path to the Manifest.
#[cfg(not(feature = "vm"))]
pub const MANIFEST_FILE: &str = "./local-enclave/qos.manifest";
/// Path to the Manifest.
#[cfg(feature = "vm")]
pub const MANIFEST_FILE: &str = "/qos.manifest";

/// Default socket for enclave <-> secure app communication.
#[cfg(not(feature = "vm"))]
pub const SEC_APP_SOCK: &str = "./local-enclave/sec_app.sock";
/// Default socket for enclave <-> secure app communication.
#[cfg(feature = "vm")]
pub const SEC_APP_SOCK: &str = "/sec_app.sock";
/// Default socket connect timeout in milliseconds
pub const DEFAULT_SOCKET_TIMEOUT_MS: &str = "5000";

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn git_sha_is_valid() {
		assert_eq!(GIT_SHA.len(), 8, "expected 8 char short SHA, got {GIT_SHA:?}");
		assert!(
			GIT_SHA.chars().all(|c| c.is_ascii_hexdigit()),
			"expected hex characters, got {GIT_SHA:?}"
		);
	}
}
