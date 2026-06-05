use std::{
	collections::BTreeMap,
	path::PathBuf,
	process::Command,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
	AppArtifact, AppEndpoint, ArtifactBuildPlan, ArtifactBuildRequest,
	ArtifactBuilder, ArtifactRequest, BuildError, BuildKey, BuildOutput,
	BuildProfile, BuildRecord, BuilderKind, HostRunnerKind, HttpResponse,
	RunnerError, RunnerKind, RunningApp, StartAppSpec, TestOutcome, TestRunner,
	endpoint_for_routes, endpoint_from_metadata, http_get, http_post,
	insert_endpoint_metadata, read_build_record, run_command, sha256_hex,
	workspace_state, write_build_record,
};

const DEFAULT_CONTAINER_PORT: u16 = 3000;
const CARGO_BIN_CONTAINERFILE: &str =
	"src/qos_test_harness/docker/cargo_bin.Containerfile";

#[derive(Debug, Clone)]
pub struct DockerRunnerConfig {
	pub workspace_root: PathBuf,
	pub output_dir: PathBuf,
	pub host: String,
	pub host_port: u16,
	pub container_port: u16,
	pub image_tag: String,
	pub keep_on_failure: bool,
}

impl DockerRunnerConfig {
	#[must_use]
	pub fn new(workspace_root: impl Into<PathBuf>, host_port: u16) -> Self {
		let workspace_root = workspace_root.into();
		Self {
			output_dir: workspace_root.join("target/qos-test-harness/docker"),
			workspace_root,
			host: "127.0.0.1".to_string(),
			host_port,
			container_port: DEFAULT_CONTAINER_PORT,
			image_tag: "qos-test-harness/cargo-bin:local".to_string(),
			keep_on_failure: false,
		}
	}
}

#[derive(Debug)]
pub struct DockerCargoBinBuilder {
	config: DockerRunnerConfig,
}

impl DockerCargoBinBuilder {
	#[must_use]
	pub fn new(config: DockerRunnerConfig) -> Self {
		Self { config }
	}

	fn record_path(&self, key: &BuildKey) -> PathBuf {
		self.config.output_dir.join(format!("{}.json", key.0))
	}

	fn build_image(
		&self,
		request: &ArtifactRequest,
	) -> Result<String, BuildError> {
		run_command(
			Command::new("make")
				.arg("out/.common-loaded")
				.current_dir(&self.config.workspace_root),
		)?;
		run_command(
			Command::new("docker")
				.arg("build")
				.arg("--platform")
				.arg("linux/amd64")
				.arg("-f")
				.arg(CARGO_BIN_CONTAINERFILE)
				.arg("--build-arg")
				.arg(format!("APPLICATION_PACKAGE={}", request.package()))
				.arg("--build-arg")
				.arg(format!("APPLICATION_BIN={}", request.bin()))
				.arg("-t")
				.arg(&self.config.image_tag)
				.arg(".")
				.current_dir(&self.config.workspace_root),
		)?;
		let image_id = run_command(
			Command::new("docker")
				.arg("image")
				.arg("inspect")
				.arg(&self.config.image_tag)
				.arg("--format")
				.arg("{{.Id}}")
				.current_dir(&self.config.workspace_root),
		)?;
		Ok(image_id.trim().to_string())
	}
}

impl ArtifactBuilder for DockerCargoBinBuilder {
	fn build_key(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildKey, BuildError> {
		let workspace = workspace_state(&plan.workspace_root);
		let raw = serde_json::json!({
			"workspace": workspace,
			"builder": plan.builder,
			"runner": plan.request.runner,
			"host_runner": plan.request.host_runner,
			"profile": plan.profile,
			"target": plan.target_triple,
			"artifact": plan.request.artifact,
			"image_tag": self.config.image_tag,
			"containerfile": CARGO_BIN_CONTAINERFILE,
			"extra": plan.extra_inputs,
		});
		Ok(BuildKey(sha256_hex(raw.to_string().as_bytes())))
	}

	async fn build(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildOutput, BuildError> {
		let key = self.build_key(plan)?;
		let record_path = self.record_path(&key);
		if let Ok(record) = read_build_record(&record_path)
			&& self.validate(&record.output).is_ok()
		{
			return Ok(record.output);
		}

		let image_id = self.build_image(&plan.request.artifact)?;
		let output = BuildOutput {
			key: key.clone(),
			builder: BuilderKind::Docker,
			runner: RunnerKind::Docker,
			host_runner: HostRunnerKind::Native,
			workspace: workspace_state(&plan.workspace_root),
			pivot: None,
			host_binaries: Vec::new(),
			enclave_binaries: Vec::new(),
			image_ref: Some(self.config.image_tag.clone()),
			image_id: Some(image_id),
			eif: None,
			rootfs: None,
			metadata: BTreeMap::new(),
		};
		self.validate(&output)?;
		write_build_record(
			&record_path,
			&BuildRecord { output: output.clone() },
		)?;
		Ok(output)
	}

	fn validate(&self, output: &BuildOutput) -> Result<(), BuildError> {
		let image_ref = output
			.image_ref
			.as_ref()
			.ok_or_else(|| BuildError::MissingArtifact("image_ref".into()))?;
		let image_id = run_command(
			Command::new("docker")
				.arg("image")
				.arg("inspect")
				.arg(image_ref)
				.arg("--format")
				.arg("{{.Id}}")
				.current_dir(&self.config.workspace_root),
		)?;
		let image_id = image_id.trim();
		if output.image_id.as_deref() != Some(image_id) {
			return Err(BuildError::InvalidOutput(format!(
				"image id mismatch for {image_ref}: record={:?} actual={image_id}",
				output.image_id
			)));
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct DockerTestRunner {
	config: DockerRunnerConfig,
	builder: DockerCargoBinBuilder,
	build_output: Option<BuildOutput>,
}

impl DockerTestRunner {
	#[must_use]
	pub fn new(config: DockerRunnerConfig) -> Self {
		let builder = DockerCargoBinBuilder::new(config.clone());
		Self { config, builder, build_output: None }
	}

	pub fn preflight(&self) -> Result<(), RunnerError> {
		run_command(Command::new("docker").arg("info"))
			.map(|_| ())
			.map_err(RunnerError::from)
	}

	fn build_plan(&self, request: ArtifactRequest) -> ArtifactBuildPlan {
		ArtifactBuildPlan {
			request: ArtifactBuildRequest {
				artifact: request,
				runner: RunnerKind::Docker,
				host_runner: HostRunnerKind::Native,
			},
			workspace_root: self.config.workspace_root.clone(),
			output_dir: self.config.output_dir.clone(),
			builder: BuilderKind::Docker,
			profile: BuildProfile::Release,
			target_triple: Some("x86_64-unknown-linux-gnu".to_string()),
			extra_inputs: BTreeMap::new(),
		}
	}

	fn endpoint(&self, spec: &StartAppSpec) -> AppEndpoint {
		let base_url =
			format!("http://{}:{}", self.config.host, self.config.host_port);
		endpoint_for_routes(
			base_url,
			&spec.health_check.path,
			&spec.public_routes,
		)
	}
}

impl TestRunner for DockerTestRunner {
	async fn prepare_artifact(
		&mut self,
		request: ArtifactRequest,
	) -> Result<AppArtifact, RunnerError> {
		self.preflight()?;
		let output = self.builder.build(&self.build_plan(request)).await?;
		let image_ref = output.image_ref.clone().ok_or_else(|| {
			RunnerError::new("docker builder returned no image")
		})?;
		let expected_digest = output.image_id.clone();
		self.build_output = Some(output);
		Ok(AppArtifact::OciImage {
			image_ref,
			pivot_path: None,
			expected_digest,
		})
	}

	async fn start_app(
		&mut self,
		spec: StartAppSpec,
	) -> Result<RunningApp, RunnerError> {
		let AppArtifact::OciImage { image_ref, .. } = &spec.artifact else {
			return Err(RunnerError::new(
				"docker runner requires an OCI image",
			));
		};
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system clock before unix epoch")
			.as_millis();
		let name = format!("qos-app-{unique}");
		let endpoint = self.endpoint(&spec);
		let mut command = Command::new("docker");
		command
			.arg("run")
			.arg("--detach")
			.arg("--rm")
			.arg("--name")
			.arg(&name)
			.arg("--publish")
			.arg(format!(
				"{}:{}:{}",
				self.config.host,
				self.config.host_port,
				self.config.container_port
			));
		for runtime_file in &spec.runtime_files {
			if !runtime_file.host_path.exists() {
				return Err(RunnerError::new(format!(
					"runtime file does not exist: {}",
					runtime_file.host_path.display()
				)));
			}
			let mut mount = format!(
				"type=bind,source={},target={}",
				runtime_file.host_path.display(),
				runtime_file.guest_path.display()
			);
			if runtime_file.read_only {
				mount.push_str(",readonly");
			}
			command.arg("--mount").arg(mount);
		}
		command.arg(image_ref).args(&spec.pivot_args);
		run_command(&mut command)?;

		let mut metadata = spec.metadata.clone();
		insert_endpoint_metadata(&mut metadata, &endpoint);
		metadata.insert("image_ref".to_string(), image_ref.clone());
		Ok(RunningApp { id: name, metadata })
	}

	async fn wait_ready(
		&mut self,
		app: &RunningApp,
		timeout: Duration,
	) -> Result<AppEndpoint, RunnerError> {
		let endpoint = endpoint_from_metadata(&app.metadata)?;
		let start = std::time::Instant::now();
		while start.elapsed() < timeout {
			if let Ok(response) = http_get(&endpoint.health_url)
				&& response.status == 200
			{
				return Ok(endpoint);
			}
			std::thread::sleep(Duration::from_millis(250));
		}
		Err(RunnerError::new(format!(
			"timed out waiting for {}",
			endpoint.health_url
		)))
	}

	async fn http_get(
		&mut self,
		url: &str,
	) -> Result<HttpResponse, RunnerError> {
		http_get(url).map_err(RunnerError::from)
	}

	async fn http_post(
		&mut self,
		url: &str,
		body: &[u8],
	) -> Result<HttpResponse, RunnerError> {
		http_post(url, body).map_err(RunnerError::from)
	}

	async fn stop_app(
		&mut self,
		app: RunningApp,
		outcome: TestOutcome,
	) -> Result<(), RunnerError> {
		if self.config.keep_on_failure
			&& matches!(outcome, TestOutcome::Failed { .. })
		{
			return Ok(());
		}
		run_command(Command::new("docker").arg("rm").arg("-f").arg(app.id))
			.map(|_| ())
			.map_err(RunnerError::from)
	}
}
