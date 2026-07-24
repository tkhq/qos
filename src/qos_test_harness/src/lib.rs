//! Reusable end-to-end test harness pieces for QOS applications.

mod artifact;
mod boot;
mod builder;
mod docker;
mod docker_qemu;
mod runner;

pub use artifact::{BinaryArtifact, Eif, ImageRef, Pivot};
pub use boot::{
	ApprovingUserMaterial, BootClientFixture, BootMaterial, KeySetMaterial,
	MaterialFile, QosReleaseMaterial,
};
pub use builder::{
	BuildError, BuildMode, BuildSelector, Builder, CargoBinaryBuilder,
	CargoProfile, ImageFileExtractBuilder, ImagePullBuilder, MakeTargetBuilder,
	OciLayoutLoadBuilder, PrebuiltQemuEifBuilder, QemuEifBaseImages,
};
pub use docker::{
	DockerMount, DockerProgram, DockerRunSpec, DockerVolumeSocket,
};
pub use docker_qemu::{
	DockerHostQemuNitroRunner, DockerHostQemuNitroRunningApp,
	DockerHostQemuNitroSpec, QemuRuntimeSpec,
};
pub use qos_core::protocol::services::boot::manifest::{
	ManifestBuilder, ManifestBuilderError, VersionedManifest,
};
pub use qos_core::protocol::services::boot::{BridgeConfig, DnsConfig};
pub use runner::{
	RunnerError, RunningApp, RunningAppGuard, StartAppSpec, TestRunner,
};
