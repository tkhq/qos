//! Core components and logic for QOS. This contains both the logic for the
//! process running in the enclave and exports for use by secure apps and QOS
//! clients
//!
//! # Maintainers Notes
//!
//! This crate should have as minimal dependencies as possible to decrease
//! supply chain attack vectors and audit burden

pub mod cli;
pub mod client;
pub mod handles;
pub mod io;
pub mod parser;
pub mod protocol;
pub mod reaper;
pub mod server;

#[cfg(feature = "egress")]
pub mod egress;

/// Path to Quorum Key secret.
pub const QUORUM_FILE: &str = "/qos.quorum.key";

/// Path to Pivot binary.
pub const PIVOT_FILE: &str = "/qos.pivot.bin";

/// Path to Ephemeral Key.
pub const EPHEMERAL_KEY_FILE: &str = "/qos.ephemeral.key";

/// Path to the Manifest.
pub const MANIFEST_FILE: &str = "/qos.manifest";

/// Default socket connect timeout in milliseconds
pub const DEFAULT_SOCKET_TIMEOUT_MS: &str = "20000";
