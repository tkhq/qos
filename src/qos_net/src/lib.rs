//! This crate contains a simple proxy server which binds to a local socket and
//! opens TCP connection.
//! It exposes a simple protocol for remote clients who
//! connect to let them manipulate these connections (read/write/flush)

#![deny(clippy::all, unsafe_code)]

pub mod error;
pub mod proxy_msg;

#[cfg(any(feature = "proxy", feature = "async_proxy"))]
pub mod cli;

#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub mod proxy_connection;
#[cfg(feature = "proxy")]
pub mod proxy_stream;

#[cfg(feature = "async_proxy")]
pub mod async_cli;
#[cfg(feature = "async_proxy")]
pub mod async_proxy;
#[cfg(feature = "async_proxy")]
pub mod async_proxy_connection;
#[cfg(feature = "async_proxy")]
pub mod async_proxy_stream;
