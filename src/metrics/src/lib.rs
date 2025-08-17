//! Minimalist metrics
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

/// metric collector
mod collector;
pub use collector::Collector;

/// metric server
mod server;
pub use server::Server;

/// re-export third party
pub use lazy_static::lazy_static;
pub use prometheus;

/// metrics
mod metrics {
    #[cfg(feature = "request")]
    pub mod request;
}

// features
#[cfg(feature = "request")]
pub use self::metrics::request;
