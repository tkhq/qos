//! This crate contains a simple proxy server to implement QOS protocol messages
//! related to establishing and using remote connections.

#![deny(clippy::all, unsafe_code)]
pub mod cli;
pub mod error;
pub mod processor;
pub mod remote_connection;
