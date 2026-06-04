use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::RunnerError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactRequest {
	SignedEcho,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArtifact {
	LocalBinary {
		path: PathBuf,
		sha256_hex: Option<String>,
	},
	OciImage {
		image_ref: String,
		pivot_path: Option<String>,
		expected_digest: Option<String>,
	},
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRouteSpec {
	pub name: String,
	pub port: Option<u16>,
	pub path: String,
}

impl HttpRouteSpec {
	#[must_use]
	pub fn new(
		name: impl Into<String>,
		port: Option<u16>,
		path: impl Into<String>,
	) -> Self {
		Self { name: name.into(), port, path: path.into() }
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAppSpec {
	pub artifact: AppArtifact,
	pub app_name: String,
	pub qos_version: Option<String>,
	pub pivot_path: Option<String>,
	pub pivot_args: Vec<String>,
	pub health_check: HttpRouteSpec,
	pub public_routes: Vec<HttpRouteSpec>,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningApp {
	pub id: String,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEndpoint {
	pub base_url: Option<String>,
	pub health_url: String,
	pub signed_echo_url: String,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSocket {
	Vsock { cid: u32, port: u32, to_host: bool },
	Unix { path: PathBuf },
	Tcp { host: String, port: u16 },
	External { control_url: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveStartSpec {
	pub artifact: AppArtifact,
	pub app_name: String,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningEnclave {
	pub id: String,
	pub control_socket: Option<RuntimeSocket>,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStartSpec {
	pub enclave_socket: RuntimeSocket,
	pub host: String,
	pub control_port: u16,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningHost {
	pub id: String,
	pub control_url: String,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
	pub status: u16,
	pub body: Vec<u8>,
}

impl HttpResponse {
	#[must_use]
	pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
		Self { status, body: body.into() }
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
	Passed,
	Failed { reason: String },
}

#[allow(async_fn_in_trait)]
pub trait EnclaveRunner {
	async fn start_enclave(
		&mut self,
		spec: EnclaveStartSpec,
	) -> Result<RunningEnclave, RunnerError>;

	async fn stop_enclave(
		&mut self,
		enclave: RunningEnclave,
		outcome: TestOutcome,
	) -> Result<(), RunnerError>;
}

#[allow(async_fn_in_trait)]
pub trait HostRunner {
	async fn start_host(
		&mut self,
		spec: HostStartSpec,
	) -> Result<RunningHost, RunnerError>;

	async fn boot_app(
		&mut self,
		host: &RunningHost,
		spec: StartAppSpec,
	) -> Result<AppEndpoint, RunnerError>;

	async fn stop_host(
		&mut self,
		host: RunningHost,
		outcome: TestOutcome,
	) -> Result<(), RunnerError>;
}

#[allow(async_fn_in_trait)]
pub trait TestRunner {
	async fn prepare_artifact(
		&mut self,
		request: ArtifactRequest,
	) -> Result<AppArtifact, RunnerError>;

	async fn start_app(
		&mut self,
		spec: StartAppSpec,
	) -> Result<RunningApp, RunnerError>;

	async fn wait_ready(
		&mut self,
		app: &RunningApp,
		timeout: Duration,
	) -> Result<AppEndpoint, RunnerError>;

	async fn http_get(
		&mut self,
		url: &str,
	) -> Result<HttpResponse, RunnerError>;

	async fn http_post(
		&mut self,
		url: &str,
		body: &[u8],
	) -> Result<HttpResponse, RunnerError>;

	async fn stop_app(
		&mut self,
		app: RunningApp,
		outcome: TestOutcome,
	) -> Result<(), RunnerError>;
}
