//! Generic app lifecycle interfaces.

use qos_core::protocol::services::boot::VersionedManifest;

/// App startup request for a concrete runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAppSpec<A> {
	/// App name.
	pub name: String,
	/// Runner-specific artifact.
	pub artifact: A,
	/// Fully built, versioned manifest for this boot.
	pub manifest: VersionedManifest,
}

/// Running app endpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningApp {
	/// Runner-specific app id.
	pub id: String,
	/// Base ingress URL for the app.
	pub ingress_url: String,
}

/// Errors produced by runners.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
	/// Runner does not support the requested operation yet.
	#[error("{0}")]
	Unsupported(String),
	/// Runner configuration is invalid.
	#[error("{0}")]
	InvalidConfig(String),
	/// Runtime command failed.
	#[error("{0}")]
	Command(String),
	/// IO error.
	#[error(transparent)]
	Io(#[from] std::io::Error),
}

/// Owned guard for a running app and its runtime resources.
#[allow(async_fn_in_trait)]
pub trait RunningAppGuard: Sized {
	/// Return the app endpoint metadata.
	fn app(&self) -> &RunningApp;

	/// Stop the app and report deterministic cleanup failures.
	async fn stop(self) -> Result<(), RunnerError>;
}

/// Generic app lifecycle runner.
#[allow(async_fn_in_trait)]
pub trait TestRunner {
	/// Artifact type this runner can start.
	type Artifact;
	/// Owned running-app guard returned by this runner.
	type Running: RunningAppGuard;

	/// Start an app.
	async fn start_app(
		&mut self,
		spec: StartAppSpec<Self::Artifact>,
	) -> Result<Self::Running, RunnerError>;
}
