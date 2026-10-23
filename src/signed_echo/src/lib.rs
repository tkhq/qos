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
use qos_attestation::cache::AttestationCache;
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
	/// The cache trusts this enclave's NSM and only parses certificate expiry.
	/// Clients verify the proof. The caller must supervise the returned task
	/// and exit if it resolves, or abort it when shutting down.
	///
	/// # Errors
	///
	/// Returns an error if the inputs cannot be loaded or encoded, or the first
	/// attestation cannot be obtained or is already expired.
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
		let (cache, task) = AttestationCache::start(
			nsm,
			VersionedManifestEnvelope::V2(envelope).manifest_hash(),
			ephemeral_public_key.clone(),
		)
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
		attestation_doc_hex: qos_hex::encode(&attestation),
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
	use std::{
		path::PathBuf,
		sync::{
			Arc,
			atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
		},
		time::Duration,
	};

	use axum::{
		Router,
		body::{Body, HttpBody},
		extract::State,
		http::{Request, StatusCode},
	};
	use tower::ServiceExt;

	use qos_attestation::{
		AttestationInputs, Error as AttestationError, VerifiedAttestation,
		cache::AttestationCache,
	};
	use qos_core::protocol::services::boot::{
		ManifestBuilder, ManifestEnvelopeV2, ManifestSet, Namespace,
		NitroConfig, QuorumMember, ShareSet, VersionedManifest,
		VersionedManifestEnvelope,
	};
	use qos_nsm::{NsmProvider, mock::MockNsm, nitro};
	use qos_p256::{P256Pair, P256Public};

	use crate::{
		BootProof, BootProofResponse, Config, SIGNED_PAYLOAD_DOMAIN,
		SignedGetUrlPayload, boot_proof_health, boot_proof_route, router,
		router_with_boot_proof, sign_json_payload,
	};

	struct RecordingNsm {
		inner: MockNsm,
		calls: AtomicUsize,
		fail: AtomicBool,
	}

	impl RecordingNsm {
		fn new(inner: MockNsm) -> Self {
			Self {
				inner,
				calls: AtomicUsize::new(0),
				fail: AtomicBool::new(false),
			}
		}
	}

	impl NsmProvider for RecordingNsm {
		fn nsm_process_request(
			&self,
			request: qos_nsm::types::NsmRequest,
		) -> qos_nsm::types::NsmResponse {
			self.calls.fetch_add(1, Ordering::SeqCst);
			if self.fail.load(Ordering::SeqCst) {
				return qos_nsm::types::NsmResponse::Error(
					qos_nsm::types::NsmErrorCode::InternalError,
				);
			}
			self.inner.nsm_process_request(request)
		}
		fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
			unreachable!("no separate timestamp request")
		}
		fn attestation_root_ca_der(&self) -> Vec<u8> {
			self.inner.attestation_root_ca_der()
		}
	}

	/// QOS's files for one enclave, in a directory removed on drop.
	struct EnclaveFiles {
		dir: PathBuf,
		key_path: PathBuf,
		manifest_path: PathBuf,
		envelope: VersionedManifestEnvelope,
		inputs: AttestationInputs,
	}

	impl EnclaveFiles {
		fn new() -> Self {
			static NEXT: AtomicU64 = AtomicU64::new(0);
			let dir = std::env::temp_dir().join(format!(
				"signed-echo-boot-proof-{}-{}",
				std::process::id(),
				NEXT.fetch_add(1, Ordering::Relaxed)
			));
			std::fs::create_dir_all(&dir).unwrap();
			let key_path = dir.join("qos.ephemeral.key");
			P256Pair::generate().unwrap().to_hex_file(&key_path).unwrap();
			let envelope = test_envelope();
			let manifest_path = dir.join("qos.manifest");
			std::fs::write(&manifest_path, envelope.to_storage_vec().unwrap())
				.unwrap();
			let key = P256Pair::from_hex_file(&key_path).unwrap();
			let inputs = AttestationInputs::new(key.public_key(), &envelope);
			Self { dir, key_path, manifest_path, envelope, inputs }
		}

		/// A mock NSM in the state QOS leaves it in after booting: PCR0-3
		/// measured, and the live and manifest-only commitments written.
		fn booted_nsm(&self) -> MockNsm {
			let inputs = &self.inputs;
			MockNsm::new()
				.with_pcr(0, inputs.pcr0.clone())
				.with_pcr(1, inputs.pcr1.clone())
				.with_pcr(2, inputs.pcr2.clone())
				.with_pcr(3, inputs.pcr3.clone())
				.with_pcr(
					17,
					nitro::expected_manifest_commitment_pcr::<nitro::Live>(
						&inputs.manifest_hash,
						&inputs.ephemeral_public_key.to_bytes(),
					)
					.unwrap()
					.to_vec(),
				)
				.with_pcr(
					18,
					nitro::expected_manifest_only_commitment_pcr(
						&inputs.manifest_hash,
					)
					.unwrap()
					.to_vec(),
				)
		}
	}

	impl Drop for EnclaveFiles {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.dir);
		}
	}

	fn test_envelope() -> VersionedManifestEnvelope {
		let members = vec![QuorumMember {
			alias: "alice".to_string(),
			pub_key: vec![2; 65],
		}];
		let VersionedManifest::V2(manifest) = ManifestBuilder::v2()
			.namespace(Namespace {
				name: "test/signed-echo".to_string(),
				nonce: 1,
				quorum_key: vec![3; 65],
			})
			.pivot_hash([1; 32])
			.manifest_set(ManifestSet {
				threshold: 1,
				members: members.clone(),
			})
			.share_set(ShareSet { threshold: 1, members })
			.enclave(NitroConfig {
				pcr0: vec![0x10; 48],
				pcr1: vec![0x11; 48],
				pcr2: vec![0x12; 48],
				pcr3: vec![0x13; 48],
				aws_root_certificate: vec![],
				qos_commit: "test".to_string(),
			})
			.build()
			.unwrap()
		else {
			unreachable!("built as v2")
		};
		VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		})
	}

	/// Exercise the router's HTTP request/response path without opening sockets.
	async fn call(app: &Router, path: &str) -> (u16, String) {
		let request = Request::builder().uri(path).body(Body::empty()).unwrap();
		let response = app.clone().oneshot(request).await.unwrap();
		let status = response.status().as_u16();
		let mut body = response.into_body();
		let mut bytes = Vec::new();
		while let Some(chunk) = body.data().await {
			bytes.extend_from_slice(&chunk.unwrap());
		}
		(status, String::from_utf8(bytes).unwrap())
	}

	#[tokio::test]
	async fn serves_cached_boot_proof_that_a_client_can_verify() {
		let files = EnclaveFiles::new();
		let nsm = Arc::new(RecordingNsm::new(files.booted_nsm()));
		let (boot_proof, task) = BootProof::start(
			nsm.clone(),
			&files.key_path,
			&files.manifest_path,
		)
		.await
		.unwrap();
		let cache_bytes = boot_proof.cache().latest().unwrap();
		let app = router_with_boot_proof(Config::new("/unused"), boot_proof);
		assert_eq!(call(&app, "/health").await.0, 200);

		let (status, body) = call(&app, "/boot_proof").await;
		assert_eq!(status, 200);
		let proof: BootProofResponse = serde_json::from_str(&body).unwrap();
		let manifest = qos_hex::decode(&proof.manifest_hex).unwrap();
		assert_eq!(
			qos_crypto::sha_256(&manifest),
			files.envelope.manifest_hash()
		);
		assert_eq!(
			VersionedManifest::try_from_slice_compat(&manifest).unwrap(),
			files.envelope.clone().manifest(),
		);
		assert_eq!(proof.manifest_version, "v2");
		assert_eq!(proof.attestation_doc_hex, qos_hex::encode(&cache_bytes));
		std::fs::remove_file(&files.key_path).unwrap();
		std::fs::remove_file(&files.manifest_path).unwrap();
		let (status, body) = call(&app, "/boot_proof").await;
		assert_eq!(status, 200);
		assert_eq!(
			serde_json::from_str::<BootProofResponse>(&body).unwrap(),
			proof
		);
		assert_eq!(
			nsm.calls.load(Ordering::SeqCst),
			1,
			"request paths only read the cache"
		);

		// Compare the served inputs with the trusted boot files before verification.
		let envelope = VersionedManifestEnvelope::try_from_slice_compat(
			&qos_hex::decode(&proof.manifest_envelope_hex).unwrap(),
		)
		.unwrap();
		assert_eq!(envelope, files.envelope);
		let ephemeral_public_key =
			qos_hex::decode(&proof.ephemeral_public_key_hex).unwrap();
		let inputs = AttestationInputs::new(
			P256Public::from_bytes(&ephemeral_public_key).unwrap(),
			&envelope,
		);
		assert_eq!(inputs, files.inputs);
		VerifiedAttestation::verify(
			qos_hex::decode(&proof.attestation_doc_hex).unwrap(),
			&files.booted_nsm().attestation_root_ca_der(),
			&inputs,
		)
		.unwrap();

		task.abort();
	}

	#[tokio::test]
	async fn startup_fails_if_the_first_nsm_request_fails() {
		let files = EnclaveFiles::new();
		let nsm = Arc::new(RecordingNsm::new(files.booted_nsm()));
		nsm.fail.store(true, Ordering::SeqCst);
		let result =
			BootProof::start(nsm, &files.key_path, &files.manifest_path).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn invalid_boot_files_fail_before_contacting_the_nsm() {
		let files = EnclaveFiles::new();
		let nsm = Arc::new(RecordingNsm::new(files.booted_nsm()));
		let mut missing_version =
			serde_json::to_value(&files.envelope).unwrap();
		missing_version["manifest"].as_object_mut().unwrap().remove("version");
		for bytes in [
			b"not a manifest".to_vec(),
			serde_json::to_vec(&missing_version).unwrap(),
		] {
			std::fs::write(&files.manifest_path, bytes).unwrap();
			let result = BootProof::start(
				nsm.clone(),
				&files.key_path,
				&files.manifest_path,
			)
			.await;
			assert!(
				matches!(result, Err(error) if error.starts_with("failed to parse v2 manifest:"))
			);
		}
		std::fs::remove_file(&files.key_path).unwrap();
		let result = BootProof::start(
			nsm.clone(),
			&files.key_path,
			&files.manifest_path,
		)
		.await;
		assert!(
			matches!(result, Err(error) if error.starts_with("failed to read ephemeral key:"))
		);
		assert_eq!(nsm.calls.load(Ordering::SeqCst), 0);
	}

	#[tokio::test(start_paused = true)]
	async fn refresh_error_keeps_serving_an_unexpired_proof() {
		let files = EnclaveFiles::new();
		let nsm = Arc::new(RecordingNsm::new(files.booted_nsm()));
		let (boot_proof, task) = BootProof::start(
			nsm.clone(),
			&files.key_path,
			&files.manifest_path,
		)
		.await
		.unwrap();
		let old = boot_proof.cache().latest().unwrap();
		nsm.fail.store(true, Ordering::SeqCst);
		// Exercise refresh failure before the current document expires.
		tokio::time::advance(
			boot_proof
				.cache()
				.valid_for()
				.saturating_sub(Duration::from_secs(1)),
		)
		.await;
		wait_for_refresh_error(boot_proof.cache()).await;
		assert!(matches!(
			&*boot_proof.cache().last_error().unwrap(),
			AttestationError::Nsm(_)
		));
		assert!(!task.is_finished(), "ordinary errors must not stop refresh");
		assert!(Arc::ptr_eq(&old, &boot_proof.cache().latest().unwrap()));
		let state = Arc::new(boot_proof);
		assert_eq!(
			boot_proof_health(State(state.clone())).await.status(),
			StatusCode::OK
		);
		assert!(boot_proof_route(State(state)).await.is_ok());
		task.abort();
	}

	async fn wait_for_refresh_error(cache: &AttestationCache) {
		let deadline = std::time::Instant::now() + Duration::from_secs(5);
		while cache.last_error().is_none() {
			assert!(
				std::time::Instant::now() < deadline,
				"refresh made no progress"
			);
			tokio::task::yield_now().await;
		}
	}

	#[tokio::test(start_paused = true)]
	async fn expired_cache_withdraws_health_and_proof() {
		let files = EnclaveFiles::new();
		let (boot_proof, task) = BootProof::start(
			Arc::new(files.booted_nsm()),
			&files.key_path,
			&files.manifest_path,
		)
		.await
		.unwrap();
		task.abort();
		let remaining = boot_proof.cache().valid_for();
		let app = router_with_boot_proof(Config::new("/unused"), boot_proof);
		tokio::time::advance(remaining).await;
		for path in ["/health", "/boot_proof"] {
			assert_eq!(call(&app, path).await.0, 503, "{path} after expiry");
		}
	}

	#[tokio::test]
	async fn default_router_has_no_boot_proof() {
		let app = router(Config::new("/unused"));
		assert_eq!(call(&app, "/health").await.0, 200);
		assert_eq!(call(&app, "/boot_proof").await.0, 404);
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
