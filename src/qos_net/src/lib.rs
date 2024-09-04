//! This crate contains a simple proxy server which binds to a local socket and
//! opens TCP connection.
//! It exposes a simple protocol for remote clients who
//! connect to let them manipulate these connections (read/write/flush)

#![deny(clippy::all, unsafe_code)]

#[cfg(feature = "proxy")]
pub mod cli;
pub mod error;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub mod proxy_connection;
pub mod proxy_msg;
pub mod proxy_stream;
