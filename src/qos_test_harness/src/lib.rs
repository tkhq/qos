//! Shared tests that can run against different QuorumOS app runners.

mod build;
mod error;
mod http;
mod runner;
pub mod runners;
mod signed_echo;

pub use build::{
	ArtifactBuildPlan, ArtifactBuildRequest, ArtifactBuilder, BuildArtifact,
	BuildError, BuildKey, BuildOutput, BuildProfile, BuildRecord, BuilderKind,
	EnclaveBinary, HostBinary, HostRunnerKind, RunnerKind, WorkspaceState,
	read_build_record, run_command, sha256_file_hex, sha256_hex,
	workspace_state, write_build_record,
};
pub use error::{RunnerError, TestError};
pub use http::{HttpClientError, http_get, http_post};
pub use runner::{
	AppArtifact, AppEndpoint, ArtifactRequest, EnclaveRunner, EnclaveStartSpec,
	HostRunner, HostStartSpec, HttpResponse, HttpRouteSpec, RunningApp,
	RunningEnclave, RunningHost, RuntimeFile, RuntimeSocket, StartAppSpec,
	TestOutcome, TestRunner,
};
pub(crate) use runner::{
	endpoint_for_routes, endpoint_from_metadata, insert_endpoint_metadata,
};
pub use signed_echo::{
	SignedEchoResponse, SignedEchoTestConfig, signed_echo_payload,
	signed_echo_startup_shutdown, verify_signed_echo_response,
};
