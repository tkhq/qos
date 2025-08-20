//! Reshard Host.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(
	clippy::missing_errors_doc,
	clippy::module_name_repetitions,
	clippy::missing_panics_doc
)]

pub mod cli;
mod host;
