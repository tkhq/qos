//! Axum-based signed echo pivot application.

use std::{
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
/// Application domain included in the signed QOS JSON payload.
const SIGNED_PAYLOAD_DOMAIN: &str = "echo app signed";

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
pub struct EchoResponse {
	/// Exact QOS JSON string covered by `signature_hex`.
	pub signed_payload_json: String,
	/// Hex-encoded quorum-key signature over `signed_payload_json` bytes.
	pub signature_hex: String,
	/// Hex-encoded quorum public key.
	pub public_key_hex: String,
}

/// Payload signed by the quorum key.
#[derive(Serialize)]
struct SignedPayload {
	domain: &'static str,
	message: String,
	time: u64,
}

/// Build the Axum router for signed echo.
pub fn router(config: Config) -> Router {
	Router::new()
		.route("/health", get(health))
		.route("/echo", post(signed_echo))
		.with_state(config)
}

async fn health() -> impl IntoResponse {
	(StatusCode::OK, Json(HealthResponse { status: "healthy" }))
}

async fn signed_echo(
	State(config): State<Config>,
	body: String,
) -> Result<Json<EchoResponse>, AppError> {
	let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let response = sign_payload(&config, time, body)?;
	Ok(Json(response))
}

fn sign_payload(
	config: &Config,
	time: u64,
	message: String,
) -> Result<EchoResponse, AppError> {
	let quorum_key = P256Pair::from_hex_file(config.quorum_key_path())
		.map_err(|_| AppError::QuorumKey)?;
	let signed_payload =
		SignedPayload { domain: SIGNED_PAYLOAD_DOMAIN, message, time };
	let signed_payload_json = qos_json::to_string(&signed_payload)
		.map_err(|_| AppError::Serialize)?;
	let signature = quorum_key
		.sign(signed_payload_json.as_bytes())
		.map_err(|_| AppError::Sign)?;

	Ok(EchoResponse {
		signed_payload_json,
		signature_hex: qos_hex::encode(&signature),
		public_key_hex: qos_hex::encode(&quorum_key.public_key().to_bytes()),
	})
}

#[derive(Debug)]
enum AppError {
	SystemTime,
	QuorumKey,
	Serialize,
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
			Self::Serialize => "failed to serialize signed payload",
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
