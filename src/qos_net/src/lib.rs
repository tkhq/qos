//! This crate contains a simple proxy server which binds to a local socket and
//! opens TCP connection.
//! It exposes a simple protocol for remote clients who
//! connect to let them manipulate these connections (read/write/flush)

/// Error types for the qos_net crate.
pub mod error;
/// Protocol messages for the proxy.
pub mod proxy_msg;

/// Proxy server implementation.
#[cfg(feature = "proxy")]
pub mod proxy;
/// Proxy connection management.
#[cfg(feature = "proxy")]
pub mod proxy_connection;
/// Proxy stream abstraction.
#[cfg(feature = "proxy")]
pub mod proxy_stream;

/// Command-line interface utilities.
#[cfg(feature = "proxy")]
pub mod cli;
