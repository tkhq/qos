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
