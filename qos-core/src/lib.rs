//! Core components of QOS.
//!
//! Any code that runs in the enclave should be contained here.
//!
//! This crate should have as minimal dependencies as possible to decrease
//! supply chain attack vectors and audit burden.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

/// Command line interface
pub mod cli;
/// Client for communicating with the enclave server
pub mod client;
/// Entry point for starting up enclave
pub mod coordinator;
/// Basic IO capabilities
pub mod io;
/// `QuorumOS` protocol details
pub mod protocol;
/// Basic socket server
pub mod server;

/// Path to Quorum Key secret.
#[cfg(not(feature = "vm"))]
pub const SECRET_FILE: &str = "./qos.secret";
/// Path to Quorum Key secret.
#[cfg(feature = "vm")]
pub const SECRET_FILE: &str = "/qos.secret";

/// Path to Pivot binary.
#[cfg(not(feature = "vm"))]
pub const PIVOT_FILE: &str = "../target/debug/pivot_ok";
/// Path to Pivot binary.
#[cfg(feature = "vm")]
pub const PIVOT_FILE: &str = "/qos.pivot";

/// Path to Ephemeral Key.
#[cfg(not(feature = "vm"))]
pub const EPHEMERAL_KEY_FILE: &str = "./qos.ephemeral.key";
/// Path to Ephemeral Key.
#[cfg(feature = "vm")]
pub const EPHEMERAL_KEY_FILE: &str = "/qos.ephemeral.key";
