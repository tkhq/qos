use std::{
	collections::BTreeMap,
	fs,
	path::{Path, PathBuf},
	process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ArtifactRequest, RunnerError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuilderKind {
	NativeCargo,
	LocalCrossCompile,
	StageX,
	Docker,
	TvcImage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerKind {
	Docker,
	LightQemu,
	ReproducibleQemu,
	Tvc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostRunnerKind {
	Native,
	Docker,
	Qemu,
	Tvc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildProfile {
	Debug,
	Release,
}

impl BuildProfile {
	#[must_use]
	pub fn as_cargo_arg(&self) -> Option<&'static str> {
		match self {
			Self::Debug => None,
			Self::Release => Some("--release"),
		}
	}

	#[must_use]
	pub fn target_dir_segment(&self) -> &'static str {
		match self {
			Self::Debug => "debug",
			Self::Release => "release",
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBuildRequest {
	pub artifact: ArtifactRequest,
	pub runner: RunnerKind,
	pub host_runner: HostRunnerKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBuildPlan {
	pub request: ArtifactBuildRequest,
	pub workspace_root: PathBuf,
	pub output_dir: PathBuf,
	pub builder: BuilderKind,
	pub profile: BuildProfile,
	pub target_triple: Option<String>,
	pub package: String,
	pub bin: String,
	pub extra_inputs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildKey(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceState {
	pub git_commit: Option<String>,
	pub dirty: bool,
	pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildArtifact {
	pub path: PathBuf,
	pub sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBinary {
	pub name: String,
	pub artifact: BuildArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveBinary {
	pub name: String,
	pub artifact: BuildArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildOutput {
	pub key: BuildKey,
	pub builder: BuilderKind,
	pub runner: RunnerKind,
	pub host_runner: HostRunnerKind,
	pub workspace: WorkspaceState,
	pub pivot: Option<BuildArtifact>,
	pub host_binaries: Vec<HostBinary>,
	pub enclave_binaries: Vec<EnclaveBinary>,
	pub image_ref: Option<String>,
	pub image_id: Option<String>,
	pub eif: Option<BuildArtifact>,
	pub rootfs: Option<BuildArtifact>,
	pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRecord {
	pub output: BuildOutput,
}

#[derive(Debug, Error)]
pub enum BuildError {
	#[error("io error: {0}")]
	Io(String),
	#[error("command failed: {0}")]
	Command(String),
	#[error("missing artifact: {0}")]
	MissingArtifact(String),
	#[error("invalid build output: {0}")]
	InvalidOutput(String),
}

impl From<BuildError> for RunnerError {
	fn from(value: BuildError) -> Self {
		Self::new(value.to_string())
	}
}

impl From<std::io::Error> for BuildError {
	fn from(value: std::io::Error) -> Self {
		Self::Io(value.to_string())
	}
}

#[allow(async_fn_in_trait)]
pub trait ArtifactBuilder {
	fn build_key(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildKey, BuildError>;

	async fn build(
		&self,
		plan: &ArtifactBuildPlan,
	) -> Result<BuildOutput, BuildError>;

	fn validate(&self, output: &BuildOutput) -> Result<(), BuildError>;
}

#[must_use]
pub fn workspace_state(workspace_root: &Path) -> WorkspaceState {
	let git_commit = command_stdout(
		Command::new("git")
			.arg("rev-parse")
			.arg("HEAD")
			.current_dir(workspace_root),
	)
	.ok();
	let dirty = !command_stdout(
		Command::new("git")
			.arg("status")
			.arg("--porcelain")
			.current_dir(workspace_root),
	)
	.unwrap_or_default()
	.is_empty();

	let fingerprint = if dirty {
		dirty_workspace_fingerprint(workspace_root)
			.unwrap_or_else(|_| "dirty-unfingerprinted".to_string())
	} else {
		git_commit.clone().unwrap_or_else(|| "unknown-clean".to_string())
	};

	WorkspaceState { git_commit, dirty, fingerprint }
}

pub fn sha256_file_hex(path: &Path) -> Result<String, BuildError> {
	let bytes = fs::read(path)?;
	Ok(sha256_hex(&bytes))
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
	let digest = Sha256::digest(bytes);
	qos_hex::encode(digest.as_slice())
}

pub fn run_command(command: &mut Command) -> Result<String, BuildError> {
	let debug = format!("{command:?}");
	let output = command.output().map_err(BuildError::from)?;
	if output.status.success() {
		let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
		combined.push_str(&String::from_utf8_lossy(&output.stderr));
		return Ok(combined);
	}

	Err(BuildError::Command(format!(
		"{debug} exited with {}: {}{}",
		output.status,
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	)))
}

fn command_stdout(command: &mut Command) -> Result<String, BuildError> {
	let output = command.output().map_err(BuildError::from)?;
	if !output.status.success() {
		return Err(BuildError::Command(format!(
			"{command:?} exited with {}",
			output.status
		)));
	}

	Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_bytes(command: &mut Command) -> Result<Vec<u8>, BuildError> {
	let output = command.output().map_err(BuildError::from)?;
	if !output.status.success() {
		return Err(BuildError::Command(format!(
			"{command:?} exited with {}",
			output.status
		)));
	}

	Ok(output.stdout)
}

fn dirty_workspace_fingerprint(
	workspace_root: &Path,
) -> Result<String, BuildError> {
	let status = command_stdout(
		Command::new("git")
			.arg("status")
			.arg("--porcelain=v1")
			.current_dir(workspace_root),
	)?;
	let diff = command_stdout(
		Command::new("git")
			.arg("diff")
			.arg("--binary")
			.current_dir(workspace_root),
	)
	.unwrap_or_default();
	let untracked = untracked_file_fingerprints(workspace_root)?;

	Ok(sha256_hex(format!("{status}\n{diff}\n{untracked}").as_bytes()))
}

fn untracked_file_fingerprints(
	workspace_root: &Path,
) -> Result<String, BuildError> {
	let output = command_bytes(
		Command::new("git")
			.arg("ls-files")
			.arg("--others")
			.arg("--exclude-standard")
			.arg("-z")
			.current_dir(workspace_root),
	)?;
	let mut fingerprints = Vec::new();
	for path in output.split(|byte| *byte == 0).filter(|path| !path.is_empty())
	{
		let path_str = String::from_utf8_lossy(path);
		let full_path = workspace_root.join(path_str.as_ref());
		if full_path.is_file() {
			let bytes = fs::read(&full_path)?;
			fingerprints.push(format!("{}\0{}", path_str, sha256_hex(&bytes)));
		}
	}
	fingerprints.sort();
	Ok(fingerprints.join("\n"))
}

pub fn write_build_record(
	path: &Path,
	record: &BuildRecord,
) -> Result<(), BuildError> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let json = serde_json::to_vec_pretty(record)
		.map_err(|err| BuildError::InvalidOutput(err.to_string()))?;
	fs::write(path, json)?;
	Ok(())
}

pub fn read_build_record(path: &Path) -> Result<BuildRecord, BuildError> {
	let bytes = fs::read(path)?;
	serde_json::from_slice(&bytes)
		.map_err(|err| BuildError::InvalidOutput(err.to_string()))
}
