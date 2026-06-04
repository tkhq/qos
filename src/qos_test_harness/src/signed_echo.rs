use std::{collections::BTreeMap, mem::size_of, time::Duration};

use qos_p256::P256Public;
use serde::{Deserialize, Serialize};

use crate::{
	AppEndpoint, ArtifactRequest, HttpResponse, HttpRouteSpec, RunningApp,
	StartAppSpec, TestError, TestOutcome, TestRunner,
};

const DEFAULT_APP_NAME: &str = "signed-echo";
const DEFAULT_ECHO_MESSAGE: &str = "vivosuite signed echo";
const DEFAULT_HEALTH_PATH: &str = "/health";
const DEFAULT_ECHO_PATH: &str = "/echo";
const DEFAULT_PIVOT_PATH: &str = "/tvc_app";
const DEFAULT_APP_PORT: u16 = 3000;
const SIGNED_ECHO_ROUTE_NAME: &str = "signed_echo";
const HEALTH_ROUTE_NAME: &str = "health";
const SIGNED_ECHO_PAYLOAD_PREFIX: &[u8] = b"echo app signed at";
const SIGNED_ECHO_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEchoTestConfig {
	pub app_name: String,
	pub readiness_timeout: Duration,
	pub health_path: String,
	pub echo_path: String,
	pub echo_message: String,
	pub qos_version: Option<String>,
	pub pivot_path: Option<String>,
	pub pivot_args: Vec<String>,
	pub health_check_port: Option<u16>,
	pub public_ingress_port: Option<u16>,
	pub metadata: BTreeMap<String, String>,
}

impl Default for SignedEchoTestConfig {
	fn default() -> Self {
		Self {
			app_name: DEFAULT_APP_NAME.to_string(),
			readiness_timeout: Duration::from_secs(240),
			health_path: DEFAULT_HEALTH_PATH.to_string(),
			echo_path: DEFAULT_ECHO_PATH.to_string(),
			echo_message: DEFAULT_ECHO_MESSAGE.to_string(),
			qos_version: None,
			pivot_path: Some(DEFAULT_PIVOT_PATH.to_string()),
			pivot_args: vec![
				"--host".to_string(),
				"0.0.0.0".to_string(),
				"--port".to_string(),
				DEFAULT_APP_PORT.to_string(),
			],
			health_check_port: Some(DEFAULT_APP_PORT),
			public_ingress_port: Some(DEFAULT_APP_PORT),
			metadata: BTreeMap::new(),
		}
	}
}

pub async fn signed_echo_startup_shutdown<R: TestRunner>(
	runner: &mut R,
	cfg: SignedEchoTestConfig,
) -> Result<(), TestError> {
	let artifact =
		runner
			.prepare_artifact(ArtifactRequest::SignedEcho)
			.await
			.map_err(|source| TestError::runner("prepare_artifact", source))?;

	let app = runner
		.start_app(StartAppSpec {
			artifact,
			app_name: cfg.app_name.clone(),
			qos_version: cfg.qos_version.clone(),
			pivot_path: cfg.pivot_path.clone(),
			pivot_args: cfg.pivot_args.clone(),
			health_check: HttpRouteSpec::new(
				HEALTH_ROUTE_NAME,
				cfg.health_check_port,
				cfg.health_path.clone(),
			),
			public_routes: vec![HttpRouteSpec::new(
				SIGNED_ECHO_ROUTE_NAME,
				cfg.public_ingress_port,
				cfg.echo_path.clone(),
			)],
			metadata: cfg.metadata.clone(),
		})
		.await
		.map_err(|source| TestError::runner("start_app", source))?;

	let test_result = run_signed_echo_checks(runner, &app, &cfg).await;
	let outcome = match &test_result {
		Ok(()) => TestOutcome::Passed,
		Err(err) => TestOutcome::Failed { reason: err.to_string() },
	};

	match (test_result, runner.stop_app(app, outcome).await) {
		(Ok(()), Ok(())) => Ok(()),
		(Err(test_error), Ok(())) => Err(test_error),
		(Ok(()), Err(source)) => Err(TestError::cleanup_after_pass(source)),
		(Err(test_error), Err(source)) => {
			Err(TestError::cleanup_after_failure(test_error, source))
		}
	}
}

async fn run_signed_echo_checks<R: TestRunner>(
	runner: &mut R,
	app: &RunningApp,
	cfg: &SignedEchoTestConfig,
) -> Result<(), TestError> {
	let endpoint = wait_ready(runner, app, cfg.readiness_timeout).await?;
	assert_health_ok(runner, &endpoint).await?;
	assert_signed_echo(runner, &endpoint, &cfg.echo_message).await
}

async fn wait_ready<R: TestRunner>(
	runner: &mut R,
	app: &RunningApp,
	timeout: Duration,
) -> Result<AppEndpoint, TestError> {
	runner
		.wait_ready(app, timeout)
		.await
		.map_err(|source| TestError::runner("wait_ready", source))
}

async fn assert_health_ok<R: TestRunner>(
	runner: &mut R,
	endpoint: &AppEndpoint,
) -> Result<(), TestError> {
	let health = runner
		.http_get(&endpoint.health_url)
		.await
		.map_err(|source| TestError::runner("http_get health", source))?;

	expect_status_ok("GET", &endpoint.health_url, &health)
}

async fn assert_signed_echo<R: TestRunner>(
	runner: &mut R,
	endpoint: &AppEndpoint,
	message: &str,
) -> Result<(), TestError> {
	let echo = runner
		.http_post(&endpoint.signed_echo_url, message.as_bytes())
		.await
		.map_err(|source| TestError::runner("http_post signed_echo", source))?;

	expect_status_ok("POST", &endpoint.signed_echo_url, &echo)?;
	verify_signed_echo_response(&echo.body, message)?;

	Ok(())
}

fn expect_status_ok(
	method: &str,
	url: &str,
	response: &HttpResponse,
) -> Result<(), TestError> {
	if response.status == 200 {
		return Ok(());
	}

	Err(TestError::assertion(format!(
		"{method} {url} returned {}: {}",
		response.status,
		truncate_body(&response.body, 4096)
	)))
}

fn truncate_body(body: &[u8], limit: usize) -> String {
	let limit = body.len().min(limit);
	let mut rendered = String::from_utf8_lossy(&body[..limit]).into_owned();
	if body.len() > limit {
		rendered.push_str("...");
	}
	rendered
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEchoResponse {
	pub time: u64,
	pub message: String,
	pub signed_payload_hex: String,
	pub signature_hex: String,
	pub public_key_hex: String,
}

pub fn verify_signed_echo_response(
	body: &[u8],
	expected_message: &str,
) -> Result<SignedEchoResponse, TestError> {
	let echo: SignedEchoResponse =
		serde_json::from_slice(body).map_err(|err| {
			TestError::assertion(format!(
				"failed to parse signed echo response: {err}"
			))
		})?;

	if echo.message != expected_message {
		return Err(TestError::assertion(format!(
			"signed echo message {:?}, want {:?}",
			echo.message, expected_message
		)));
	}

	let want_payload = signed_echo_payload(echo.time, expected_message);
	let got_payload =
		decode_hex("signed echo payload", &echo.signed_payload_hex)?;

	if got_payload != want_payload {
		return Err(TestError::assertion("signed echo payload mismatch"));
	}

	let signature = decode_hex("signed echo signature", &echo.signature_hex)?;
	if signature.len() != SIGNED_ECHO_SIGNATURE_LEN {
		return Err(TestError::assertion(format!(
			"signed echo signature must be {SIGNED_ECHO_SIGNATURE_LEN} bytes, got {}",
			signature.len()
		)));
	}

	let public_key =
		decode_hex("signed echo public key", &echo.public_key_hex)?;
	let public = P256Public::from_bytes(&public_key).map_err(|err| {
		TestError::assertion(format!(
			"signed echo public key is not a valid 130-byte QOS P-256 public key: {err:?}"
		))
	})?;

	public.verify(&want_payload, &signature).map_err(|err| {
		TestError::assertion(format!(
			"signed echo signature verification failed: {err:?}"
		))
	})?;

	Ok(echo)
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, TestError> {
	qos_hex::decode(value).map_err(|err| {
		TestError::assertion(format!("failed to decode {label}: {err:?}"))
	})
}

#[must_use]
pub fn signed_echo_payload(timestamp: u64, message: &str) -> Vec<u8> {
	let mut payload = Vec::with_capacity(
		SIGNED_ECHO_PAYLOAD_PREFIX.len() + size_of::<u64>() + message.len(),
	);
	payload.extend_from_slice(SIGNED_ECHO_PAYLOAD_PREFIX);
	payload.extend_from_slice(&timestamp.to_be_bytes());
	payload.extend_from_slice(message.as_bytes());
	payload
}
