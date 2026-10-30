//! Axum-based signed echo pivot application.

use std::{
	path::{Path, PathBuf},
	sync::Arc,
	time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use axum::{
	Json, Router,
	extract::{Query, State},
	http::StatusCode,
	response::{IntoResponse, Response},
	routing::{get, post},
};
use qos_attestation::{AttestationInputs, cache::AttestationCache};
use qos_core::protocol::services::boot::{
	ManifestEnvelopeV2, VersionedManifestEnvelope,
};
use qos_nsm::NsmProvider;
use qos_p256::{P256Pair, P256Public};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

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
struct SignedEchoPayload {
	domain: &'static str,
	message: String,
	time: u64,
}

/// Payload signed by the quorum key for fetched URL responses.
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SignedGetUrlPayload {
	/// Application domain included in the signed payload.
	pub domain: String,
	/// URL fetched by the app.
	pub url: String,
	/// HTTP status returned by the fetched URL.
	#[serde(with = "qos_json::string_or_numeric")]
	pub status: u16,
	/// Response body returned by the fetched URL.
	pub body: String,
	/// Unix timestamp when the response was signed.
	#[serde(with = "qos_json::string_or_numeric")]
	pub time: u64,
}

#[derive(Deserialize)]
struct GetUrlQuery {
	url: String,
}

/// A boot proof's parts, as served by `/boot_proof`. Byte fields are hex.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BootProofResponse {
	/// Original `COSE_Sign1` document from the NSM. Clients must verify it.
	pub attestation_doc_hex: String,
	/// Canonical JSON manifest bytes. Their SHA-256 is the document's `user_data`.
	pub manifest_hex: String,
	/// Canonical JSON manifest envelope bytes.
	pub manifest_envelope_hex: String,
	/// Manifest schema version: `"v2"`.
	pub manifest_version: String,
	/// The live ephemeral public key the document attests.
	pub ephemeral_public_key_hex: String,
}

/// Fixed boot inputs and the cache used to serve this enclave's boot proof.
pub struct BootProof {
	cache: AttestationCache,
	manifest: Vec<u8>,
	manifest_envelope: Vec<u8>,
	ephemeral_public_key: P256Public,
}

impl BootProof {
	/// Load the live public key and v2 manifest, then start the cache.
	///
	/// The cache verifies documents against the boot inputs and NSM root.
	/// The caller must supervise the returned task and exit if it resolves,
	/// or abort it when shutting down.
	///
	/// # Errors
	///
	/// Returns an error if the inputs cannot be loaded or encoded, or the first
	/// attestation cannot be obtained, verified, or is already expired.
	pub async fn start<P: NsmProvider + 'static>(
		nsm: Arc<P>,
		ephemeral_key_path: &Path,
		manifest_path: &Path,
	) -> Result<(Self, JoinHandle<()>), String> {
		let ephemeral_public_key = P256Pair::from_hex_file(ephemeral_key_path)
			.map_err(|e| format!("failed to read ephemeral key: {e:?}"))?
			.public_key();
		let manifest_bytes = std::fs::read(manifest_path)
			.map_err(|e| format!("failed to read manifest: {e}"))?;
		let envelope: ManifestEnvelopeV2 =
			serde_json::from_slice(&manifest_bytes)
				.map_err(|e| format!("failed to parse v2 manifest: {e}"))?;
		let manifest = qos_json::to_vec(&envelope.manifest)
			.map_err(|e| format!("failed to encode manifest: {e}"))?;
		let manifest_envelope = qos_json::to_vec(&envelope)
			.map_err(|e| format!("failed to encode manifest envelope: {e}"))?;
		let inputs = AttestationInputs::new(
			ephemeral_public_key.clone(),
			&VersionedManifestEnvelope::V2(envelope),
		);
		let (cache, task) = AttestationCache::start(nsm, inputs)
			.await
			.map_err(|e| format!("failed to start attestation cache: {e}"))?;
		Ok((
			Self { cache, manifest, manifest_envelope, ephemeral_public_key },
			task,
		))
	}

	/// The cache, for readiness and expiry/error diagnostics.
	#[must_use]
	pub fn cache(&self) -> &AttestationCache {
		&self.cache
	}
}

/// Build the Axum router for signed echo.
pub fn router(config: Config) -> Router {
	quorum_routes(config).route("/health", get(health))
}

/// Add cached boot-proof serving and readiness to the signed echo router.
pub fn router_with_boot_proof(config: Config, boot_proof: BootProof) -> Router {
	let proof_routes = Router::new()
		.route("/health", get(boot_proof_health))
		.route("/boot_proof", get(boot_proof_route))
		.with_state(Arc::new(boot_proof));
	quorum_routes(config).merge(proof_routes)
}

fn quorum_routes(config: Config) -> Router {
	Router::new()
		.route("/echo", post(signed_echo))
		.route("/get_url", get(signed_get_url))
		.with_state(config)
}

async fn health() -> impl IntoResponse {
	(StatusCode::OK, Json(HealthResponse { status: "healthy" }))
}

async fn boot_proof_health(
	State(boot_proof): State<Arc<BootProof>>,
) -> Response {
	if boot_proof.cache.has_unexpired_document() {
		(StatusCode::OK, Json(HealthResponse { status: "healthy" }))
			.into_response()
	} else {
		AppError::NoAttestation.into_response()
	}
}

async fn boot_proof_route(
	State(boot_proof): State<Arc<BootProof>>,
) -> Result<Json<BootProofResponse>, AppError> {
	let attestation =
		boot_proof.cache.latest().ok_or(AppError::NoAttestation)?;
	Ok(Json(BootProofResponse {
		attestation_doc_hex: qos_hex::encode(attestation.document()),
		manifest_hex: qos_hex::encode(&boot_proof.manifest),
		manifest_envelope_hex: qos_hex::encode(&boot_proof.manifest_envelope),
		manifest_version: "v2".to_string(),
		ephemeral_public_key_hex: qos_hex::encode(
			&boot_proof.ephemeral_public_key.to_bytes(),
		),
	}))
}

async fn signed_echo(
	State(config): State<Config>,
	body: String,
) -> Result<Json<EchoResponse>, AppError> {
	let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let response = sign_payload(&config, time, body)?;
	Ok(Json(response))
}

async fn signed_get_url(
	State(config): State<Config>,
	Query(query): Query<GetUrlQuery>,
) -> Result<Json<EchoResponse>, AppError> {
	let url = query.url;
	let fetch_url = url.clone();
	let fetched =
		tokio::task::spawn_blocking(move || fetch(&fetch_url)).await.map_err(
			|err| AppError::Fetch(format!("fetch task failed: {err}")),
		)??;
	let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let payload = SignedGetUrlPayload {
		domain: SIGNED_PAYLOAD_DOMAIN.to_string(),
		url,
		status: fetched.status,
		body: fetched.body,
		time,
	};
	let response = sign_json_payload(&config, &payload)?;
	Ok(Json(response))
}

fn sign_payload(
	config: &Config,
	time: u64,
	message: String,
) -> Result<EchoResponse, AppError> {
	let signed_payload =
		SignedEchoPayload { domain: SIGNED_PAYLOAD_DOMAIN, message, time };
	sign_json_payload(config, &signed_payload)
}

fn sign_json_payload(
	config: &Config,
	payload: &impl Serialize,
) -> Result<EchoResponse, AppError> {
	let quorum_key = P256Pair::from_hex_file(config.quorum_key_path())
		.map_err(|_| AppError::QuorumKey)?;
	let signed_payload_json =
		qos_json::to_string(payload).map_err(|_| AppError::Serialize)?;
	let signature = quorum_key
		.sign(signed_payload_json.as_bytes())
		.map_err(|_| AppError::Sign)?;

	Ok(EchoResponse {
		signed_payload_json,
		signature_hex: qos_hex::encode(&signature),
		public_key_hex: qos_hex::encode(&quorum_key.public_key().to_bytes()),
	})
}

struct FetchedUrl {
	status: u16,
	body: String,
}

fn fetch(url: &str) -> Result<FetchedUrl, AppError> {
	let response = ureq::AgentBuilder::new()
		.timeout(Duration::from_secs(15))
		.build()
		.get(url)
		.call()
		.map_err(|err| AppError::Fetch(err.to_string()))?;
	let status = response.status();
	if !(200..300).contains(&status) {
		return Err(AppError::FetchStatus(status));
	}
	let body = response
		.into_string()
		.map_err(|err| AppError::FetchRead(err.to_string()))?;
	Ok(FetchedUrl { status, body })
}

#[derive(Debug)]
enum AppError {
	SystemTime,
	QuorumKey,
	Serialize,
	Sign,
	Fetch(String),
	FetchStatus(u16),
	FetchRead(String),
	NoAttestation,
}

impl From<SystemTimeError> for AppError {
	fn from(_err: SystemTimeError) -> Self {
		Self::SystemTime
	}
}

impl IntoResponse for AppError {
	fn into_response(self) -> Response {
		let status = match &self {
			Self::Fetch(_) | Self::FetchStatus(_) | Self::FetchRead(_) => {
				StatusCode::BAD_GATEWAY
			}
			Self::NoAttestation => StatusCode::SERVICE_UNAVAILABLE,
			_ => StatusCode::INTERNAL_SERVER_ERROR,
		};
		let error = match &self {
			Self::SystemTime => {
				"system time is before the Unix epoch".to_string()
			}
			Self::QuorumKey => "failed to read quorum key".to_string(),
			Self::Serialize => "failed to serialize signed payload".to_string(),
			Self::Sign => "failed to sign payload".to_string(),
			Self::Fetch(err) => format!("failed to fetch url: {err}"),
			Self::FetchStatus(status) => {
				format!("fetched url returned non-success status: {status}")
			}
			Self::FetchRead(err) => {
				format!("failed to read fetched url response: {err}")
			}
			Self::NoAttestation => {
				"no unexpired attestation document".to_string()
			}
		};
		(status, Json(ErrorResponse { error })).into_response()
	}
}

#[derive(Serialize)]
struct ErrorResponse {
	error: String,
}

#[derive(Serialize)]
struct HealthResponse {
	status: &'static str,
}

#[cfg(test)]
mod tests {
	use axum::{http::StatusCode, response::IntoResponse};
	use qos_p256::{P256Pair, P256Public};

	use crate::{
		Config, SIGNED_PAYLOAD_DOMAIN, SignedGetUrlPayload, health,
		sign_json_payload,
	};

	#[tokio::test]
	async fn health_returns_ok() {
		assert_eq!(health().await.into_response().status(), StatusCode::OK);
	}

	#[test]
	fn signs_get_url_payload_shape() {
		let key_path = std::env::temp_dir()
			.join(format!("signed-echo-get-url-{}.secret", std::process::id()));
		let pair = P256Pair::generate().unwrap();
		pair.to_hex_file(&key_path).unwrap();
		let config = Config::new(&key_path);
		let payload = SignedGetUrlPayload {
			domain: SIGNED_PAYLOAD_DOMAIN.to_string(),
			url: "https://example.com/".to_string(),
			status: 200,
			body: "Example Domain".to_string(),
			time: 1,
		};

		let response = sign_json_payload(&config, &payload).unwrap();
		let signed_payload: SignedGetUrlPayload =
			serde_json::from_str(&response.signed_payload_json).unwrap();
		let public_key = P256Public::from_bytes(
			&qos_hex::decode(&response.public_key_hex).unwrap(),
		)
		.unwrap();
		let signature = qos_hex::decode(&response.signature_hex).unwrap();

		assert_eq!(signed_payload, payload);
		public_key
			.verify(response.signed_payload_json.as_bytes(), &signature)
			.unwrap();

		std::fs::remove_file(key_path).unwrap();
	}
}
