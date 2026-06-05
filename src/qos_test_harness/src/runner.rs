use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::RunnerError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactRequest {
	CargoBin { package: String, bin: String },
}

impl ArtifactRequest {
	#[must_use]
	pub fn cargo_bin(
		package: impl Into<String>,
		bin: impl Into<String>,
	) -> Self {
		Self::CargoBin { package: package.into(), bin: bin.into() }
	}

	#[must_use]
	pub fn package(&self) -> &str {
		match self {
			Self::CargoBin { package, .. } => package,
		}
	}

	#[must_use]
	pub fn bin(&self) -> &str {
		match self {
			Self::CargoBin { bin, .. } => bin,
		}
	}
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
pub struct RuntimeFile {
	pub host_path: PathBuf,
	pub guest_path: PathBuf,
	pub read_only: bool,
}

impl RuntimeFile {
	#[must_use]
	pub fn read_only(
		host_path: impl Into<PathBuf>,
		guest_path: impl Into<PathBuf>,
	) -> Self {
		Self {
			host_path: host_path.into(),
			guest_path: guest_path.into(),
			read_only: true,
		}
	}
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
	pub runtime_files: Vec<RuntimeFile>,
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
	pub public_urls: BTreeMap<String, String>,
	pub metadata: BTreeMap<String, String>,
}

const ENDPOINT_BASE_URL_METADATA: &str = "endpoint_base_url";
const ENDPOINT_HEALTH_URL_METADATA: &str = "endpoint_health_url";
const ENDPOINT_PUBLIC_URL_PREFIX: &str = "endpoint_public_url.";

pub(crate) fn endpoint_for_routes(
	base_url: String,
	health_path: &str,
	public_routes: &[HttpRouteSpec],
) -> AppEndpoint {
	let public_urls = public_routes
		.iter()
		.map(|route| {
			(route.name.clone(), format!("{}{}", base_url, route.path))
		})
		.collect();
	AppEndpoint {
		base_url: Some(base_url.clone()),
		health_url: format!("{base_url}{health_path}"),
		public_urls,
		metadata: BTreeMap::new(),
	}
}

pub(crate) fn insert_endpoint_metadata(
	metadata: &mut BTreeMap<String, String>,
	endpoint: &AppEndpoint,
) {
	if let Some(base_url) = endpoint.base_url.as_ref() {
		metadata
			.insert(ENDPOINT_BASE_URL_METADATA.to_string(), base_url.clone());
	}
	metadata.insert(
		ENDPOINT_HEALTH_URL_METADATA.to_string(),
		endpoint.health_url.clone(),
	);
	for (name, url) in &endpoint.public_urls {
		metadata
			.insert(format!("{ENDPOINT_PUBLIC_URL_PREFIX}{name}"), url.clone());
	}
}

pub(crate) fn endpoint_from_metadata(
	metadata: &BTreeMap<String, String>,
) -> Result<AppEndpoint, RunnerError> {
	let health_url = metadata
		.get(ENDPOINT_HEALTH_URL_METADATA)
		.cloned()
		.ok_or_else(|| RunnerError::new("running app has no health URL"))?;
	let base_url = metadata.get(ENDPOINT_BASE_URL_METADATA).cloned();
	let public_urls = metadata
		.iter()
		.filter_map(|(key, value)| {
			key.strip_prefix(ENDPOINT_PUBLIC_URL_PREFIX)
				.map(|name| (name.to_string(), value.clone()))
		})
		.collect();
	Ok(AppEndpoint {
		base_url,
		health_url,
		public_urls,
		metadata: metadata.clone(),
	})
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
