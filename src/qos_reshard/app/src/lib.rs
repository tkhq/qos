//! Reshard
#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![warn(missing_docs, clippy::pedantic)]

pub mod cli;

mod service;

mod routes {
	pub(crate) mod retrieve_reshard;
}
