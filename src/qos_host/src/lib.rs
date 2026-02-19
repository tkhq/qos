//! Enclave host implementation. The host primarily consists of a HTTP server
//! that proxies requests to the enclave by establishing a client connection
//! with the enclave.
//!
//! # IMPLEMENTERS NOTE
//!
//! The host HTTP server is currently implemented using the `axum` framework.
//! This may be swapped out in the the future in favor of a lighter package in
//! order to slim the dependency tree. In the mean time, these resources can
//! help familiarize you with the abstractions:
//!
//! * Request body extractors: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/extract.md/>
//! * Response: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/response.md/>
//! * Responding with error: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/error_handling.md/>

use axum::{
	http::StatusCode,
	response::{IntoResponse, Response},
	Json,
};
use qos_core::protocol::{
	services::boot::ManifestEnvelope, Hash256, ProtocolPhase,
};

pub mod cli;
pub mod host;

/// Crate version of the host binary, sourced from `Cargo.toml`.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit SHA of the host binary build, set by `build.rs`.
pub const GIT_SHA: &str = env!("GIT_SHA");

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 256 * MEGABYTE;

/// Simple error that implements [`IntoResponse`] so it can
/// be returned from handlers as an http response (and not get silently
/// dropped).
struct Error(String);

impl IntoResponse for Error {
	fn into_response(self) -> Response {
		let body = JsonError { error: self.0 };
		eprintln!("qos_host error: {body:?}");

		// In the future we may want to change `Error` into an enum
		// indicating what status code to use. For now it will always be
		// an internal error since we don't need to express other error types.
		(StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
	}
}

const HOST_HEALTH: &str = "/host-health";
const ENCLAVE_HEALTH: &str = "/enclave-health";
const MESSAGE: &str = "/message";
const ENCLAVE_INFO: &str = "/enclave-info";

/// Response body to the `/enclave-info` endpoint.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveInfo {
	/// Current phase of the enclave.
	pub phase: ProtocolPhase,
	/// Manifest envelope in the enclave.
	pub manifest_envelope: Option<ManifestEnvelope>,
	/// Crate version of the host binary.
	pub host_version: String,
	/// Git commit SHA of the host binary build.
	pub host_build_sha: String,
}

/// Vitals we just use for logging right now to avoid logging the entire
/// manifest.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveVitalStats {
	phase: ProtocolPhase,
	namespace: String,
	nonce: u32,
	#[serde(with = "qos_hex::serde")]
	pivot_hash: Hash256,
	#[serde(with = "qos_hex::serde")]
	pcr0: Vec<u8>,
	pivot_args: Vec<String>,
}

/// Body of a 4xx or 5xx response
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct JsonError {
	/// Error message.
	pub error: String,
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn git_sha_is_valid() {
		assert_eq!(
			GIT_SHA.len(),
			8,
			"expected 8 char short SHA, got {GIT_SHA:?}"
		);
		assert!(
			GIT_SHA.chars().all(|c| c.is_ascii_hexdigit()),
			"expected hex characters, got {GIT_SHA:?}"
		);
	}
}
