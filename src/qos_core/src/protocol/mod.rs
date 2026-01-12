//! Quorum protocol
//!
//! This module contains the protocol types and logic for QuorumOS.
//!
//! Protocol types are defined in [`qos_proto`] using Protocol Buffers
//! for cross-language interoperability and deterministic encoding.

mod error;
pub mod msg;
pub mod services;
mod state;

pub use error::ProtocolError;
pub use state::ProtocolPhase;
pub(crate) use state::ProtocolState;

pub(crate) mod processor;
pub use processor::INITIAL_CLIENT_TIMEOUT;

/// 256-bit hash.
pub type Hash256 = [u8; 32];
