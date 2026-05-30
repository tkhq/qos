//! Axum-based signed echo pivot application.

use std::{
	mem::size_of,
	path::{Path, PathBuf},
	time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use axum::{
	Json, Router,
	extract::State,
	http::StatusCode,
	response::{IntoResponse, Response},
	routing::{get, post},
};
use qos_p256::P256Pair;
use serde::{Deserialize, Serialize};

/// Default path where QOS writes the quorum-key secret for pivot apps.
pub const DEFAULT_QUORUM_KEY_PATH: &str = "/qos.quorum.key";
/// Domain separator for signed echo proofs.
pub const DOMAIN_SEPARATOR: &str = "echo app signed at";

/// Runtime configuration for the signed echo app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
	quorum_key_path: PathBuf,
}

impl Config {
	/// Create a runtime config.
	#[must_use]
	pub fn new(quorum_key_path: impl Into<PathBuf>) -> Self {
		Self { quorum_key_path: quorum_key_path.into() }
	}

	/// Create a config using the default QOS quorum-key path.
	#[must_use]
	pub fn with_qos_defaults() -> Self {
		Self::new(DEFAULT_QUORUM_KEY_PATH)
	}

	/// Return the configured quorum-key path.
	#[must_use]
	pub fn quorum_key_path(&self) -> &Path {
		&self.quorum_key_path
	}
}

/// Response returned by the signed echo endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SignedEchoResponse {
	/// Unix timestamp, in seconds, included in the signed payload.
	pub time: u64,
	/// Request body echoed back as UTF-8 text.
	pub message: String,
	/// Hex-encoded quorum-key signature preimage.
	pub signed_payload_hex: String,
	/// Hex-encoded quorum-key signature over the bytes represented by
	/// `signed_payload_hex`.
	pub signature_hex: String,
	/// Hex-encoded quorum public key.
	pub public_key_hex: String,
}

/// Build the Axum router for signed echo.
pub fn router(config: Config) -> Router {
	Router::new()
		.route("/health", get(health))
		.route("/echo", post(signed_echo))
		.route("/signed-echo", post(signed_echo))
		.route("/signed_echo", post(signed_echo))
		.with_state(config)
}

async fn health() -> impl IntoResponse {
	(StatusCode::OK, Json(HealthResponse { status: "healthy" }))
}

async fn signed_echo(
	State(config): State<Config>,
	body: String,
) -> Result<Json<SignedEchoResponse>, AppError> {
	let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let response = sign_payload(&config, time, body)?;
	Ok(Json(response))
}

fn sign_payload(
	config: &Config,
	time: u64,
	message: String,
) -> Result<SignedEchoResponse, AppError> {
	let quorum_key = P256Pair::from_hex_file(config.quorum_key_path())
		.map_err(|_| AppError::QuorumKey)?;
	let signed_payload = signature_preimage(time, &message);
	let signature =
		quorum_key.sign(&signed_payload).map_err(|_| AppError::Sign)?;

	Ok(SignedEchoResponse {
		time,
		message,
		signed_payload_hex: qos_hex::encode(&signed_payload),
		signature_hex: qos_hex::encode(&signature),
		public_key_hex: qos_hex::encode(&quorum_key.public_key().to_bytes()),
	})
}

fn signature_preimage(time: u64, message: &str) -> Vec<u8> {
	let mut signed_payload = Vec::with_capacity(
		DOMAIN_SEPARATOR.len() + size_of::<u64>() + message.len(),
	);
	signed_payload.extend_from_slice(DOMAIN_SEPARATOR.as_bytes());
	signed_payload.extend_from_slice(&time.to_be_bytes());
	signed_payload.extend_from_slice(message.as_bytes());
	signed_payload
}

#[derive(Debug)]
enum AppError {
	SystemTime,
	QuorumKey,
	Sign,
}

impl From<SystemTimeError> for AppError {
	fn from(_err: SystemTimeError) -> Self {
		Self::SystemTime
	}
}

impl IntoResponse for AppError {
	fn into_response(self) -> Response {
		let error = match self {
			Self::SystemTime => "system time is before the Unix epoch",
			Self::QuorumKey => "failed to read quorum key",
			Self::Sign => "failed to sign payload",
		};
		(StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error }))
			.into_response()
	}
}

#[derive(Serialize)]
struct ErrorResponse {
	error: &'static str,
}

#[derive(Serialize)]
struct HealthResponse {
	status: &'static str,
}
