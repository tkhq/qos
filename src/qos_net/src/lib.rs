#![doc = include_str!("../README.md")]

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
