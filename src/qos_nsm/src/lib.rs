//! Endpoints and types for an enclaves attestation flow.

pub mod nitro;
mod nsm;
pub mod types;

pub use nsm::{Nsm, NsmProvider};

#[cfg(any(feature = "mock", test))]
pub mod mock;
