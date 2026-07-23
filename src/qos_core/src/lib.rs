#![doc = include_str!("../README.md")]
#![allow(clippy::doc_markdown)]

pub mod cli;
pub mod client;
pub mod handles;
pub mod io;
pub mod parser;
pub mod protocol;
pub mod reaper;
pub mod server;
pub mod verify;

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
