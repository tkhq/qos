//! Builder for v2 manifests.

use crate::protocol::{
	Hash256,
	services::boot::{
		BridgeConfig, Manifest, ManifestSet, Namespace, NitroConfig, PatchSet,
		PivotConfig, PivotConfigV2, PivotEnv, RestartPolicy, ShareSet,
	},
};

use super::{DnsConfig, ManifestV2, ManifestVersion, VersionedManifest};

/// An error returned when a required manifest value was not provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManifestBuilderError {
	/// The manifest namespace was not provided.
	#[error("missing required manifest field: namespace")]
	MissingNamespace,
	/// The pivot binary hash was not provided.
	#[error("missing required manifest field: pivot hash")]
	MissingPivotHash,
	/// The manifest approval set was not provided.
	#[error("missing required manifest field: manifest set")]
	MissingManifestSet,
	/// The share approval set was not provided.
	#[error("missing required manifest field: share set")]
	MissingShareSet,
	/// The enclave configuration was not provided.
	#[error("missing required manifest field: enclave configuration")]
	MissingEnclave,
	/// The patch approval set was not provided for a v1 manifest.
	#[error("missing required manifest field: patch set")]
	MissingPatchSet,
	/// A v1 manifest cannot contain pivot environment configuration.
	#[error("manifest v1 does not support pivot environment configuration")]
	V1DoesNotSupportPivotEnv,
	/// A v1 manifest cannot contain DNS configuration.
	#[error("manifest v1 does not support DNS configuration")]
	V1DoesNotSupportDns,
	/// A v2 manifest cannot contain a patch approval set.
	#[error("manifest v2 does not support a patch set")]
	V2DoesNotSupportPatchSet,
}

/// Builds a versioned manifest using either the v1 or v2 schema.
///
/// Identity and trust inputs are required. Runtime options use conservative
/// defaults when omitted: the pivot is never restarted, bridge rules and
/// arguments are empty, debug mode is disabled, the environment is empty,
/// and DNS is not configured.
#[derive(Debug, Clone)]
pub struct ManifestBuilder {
	version: Option<ManifestVersion>,
	namespace: Option<Namespace>,
	pivot_hash: Option<Hash256>,
	restart_policy: Option<RestartPolicy>,
	bridge_config: Option<Vec<BridgeConfig>>,
	debug_mode: Option<bool>,
	pivot_args: Option<Vec<String>>,
	pivot_env: Option<PivotEnv>,
	manifest_set: Option<ManifestSet>,
	share_set: Option<ShareSet>,
	enclave: Option<NitroConfig>,
	patch_set: Option<PatchSet>,
	dns: Option<DnsConfig>,
}

impl Default for ManifestBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl ManifestBuilder {
	/// Create an empty v2 manifest builder.
	#[must_use]
	pub fn new() -> Self {
		Self {
			version: None,
			namespace: None,
			pivot_hash: None,
			restart_policy: None,
			bridge_config: None,
			debug_mode: None,
			pivot_args: None,
			pivot_env: None,
			manifest_set: None,
			share_set: None,
			enclave: None,
			patch_set: None,
			dns: None,
		}
	}

	/// Create an empty v1 manifest builder.
	#[must_use]
	pub fn v1() -> Self {
		Self::new().with_version(ManifestVersion::V1)
	}

	/// Create an empty v2 manifest builder.
	#[must_use]
	pub fn v2() -> Self {
		Self::new().with_version(ManifestVersion::V2)
	}

	/// Select the manifest schema version to build.
	#[must_use]
	pub fn with_version(mut self, version: ManifestVersion) -> Self {
		self.version = Some(version);
		self
	}

	/// Set the namespace configuration.
	#[must_use]
	pub fn namespace(mut self, namespace: Namespace) -> Self {
		self.namespace = Some(namespace);
		self
	}

	/// Set the pivot binary hash.
	#[must_use]
	pub fn pivot_hash(mut self, pivot_hash: Hash256) -> Self {
		self.pivot_hash = Some(pivot_hash);
		self
	}

	/// Set the pivot restart policy.
	#[must_use]
	pub fn restart_policy(mut self, restart_policy: RestartPolicy) -> Self {
		self.restart_policy = Some(restart_policy);
		self
	}

	/// Set the pivot bridge rules.
	#[must_use]
	pub fn bridge_config(mut self, bridge_config: Vec<BridgeConfig>) -> Self {
		self.bridge_config = Some(bridge_config);
		self
	}

	/// Set whether the pivot runs in debug mode.
	#[must_use]
	pub fn debug_mode(mut self, debug_mode: bool) -> Self {
		self.debug_mode = Some(debug_mode);
		self
	}

	/// Set the arguments passed to the pivot binary.
	#[must_use]
	pub fn pivot_args(mut self, pivot_args: Vec<String>) -> Self {
		self.pivot_args = Some(pivot_args);
		self
	}

	/// Set the environment passed to the pivot binary.
	#[must_use]
	pub fn pivot_env(mut self, pivot_env: PivotEnv) -> Self {
		self.pivot_env = Some(pivot_env);
		self
	}

	/// Set the manifest approval set.
	#[must_use]
	pub fn manifest_set(mut self, manifest_set: ManifestSet) -> Self {
		self.manifest_set = Some(manifest_set);
		self
	}

	/// Set the share approval set.
	#[must_use]
	pub fn share_set(mut self, share_set: ShareSet) -> Self {
		self.share_set = Some(share_set);
		self
	}

	/// Set the enclave configuration.
	#[must_use]
	pub fn enclave(mut self, enclave: NitroConfig) -> Self {
		self.enclave = Some(enclave);
		self
	}

	/// Set the patch approval set required by v1 manifests.
	#[must_use]
	pub fn patch_set(mut self, patch_set: PatchSet) -> Self {
		self.patch_set = Some(patch_set);
		self
	}

	/// Set the DNS configuration.
	#[must_use]
	pub fn dns(mut self, dns: DnsConfig) -> Self {
		self.dns = Some(dns);
		self
	}

	/// Build the manifest in its version-preserving wrapper.
	///
	/// # Errors
	///
	/// Returns [`ManifestBuilderError`] when required configuration is omitted
	/// or supplied for an incompatible schema.
	pub fn build(self) -> Result<VersionedManifest, ManifestBuilderError> {
		let namespace =
			self.namespace.ok_or(ManifestBuilderError::MissingNamespace)?;
		let pivot_hash =
			self.pivot_hash.ok_or(ManifestBuilderError::MissingPivotHash)?;
		let manifest_set = self
			.manifest_set
			.ok_or(ManifestBuilderError::MissingManifestSet)?;
		let share_set =
			self.share_set.ok_or(ManifestBuilderError::MissingShareSet)?;
		let enclave =
			self.enclave.ok_or(ManifestBuilderError::MissingEnclave)?;

		let restart = self.restart_policy.unwrap_or(RestartPolicy::Never);
		let bridge_config = self.bridge_config.unwrap_or_default();
		let debug_mode = self.debug_mode.unwrap_or(false);
		let args = self.pivot_args.unwrap_or_default();

		match self.version.unwrap_or_default() {
			ManifestVersion::V1 => {
				if self.pivot_env.is_some() {
					return Err(ManifestBuilderError::V1DoesNotSupportPivotEnv);
				}
				if self.dns.is_some() {
					return Err(ManifestBuilderError::V1DoesNotSupportDns);
				}
				let patch_set = self
					.patch_set
					.ok_or(ManifestBuilderError::MissingPatchSet)?;

				Ok(VersionedManifest::V1(Manifest {
					namespace,
					pivot: PivotConfig {
						hash: pivot_hash,
						restart,
						bridge_config,
						debug_mode,
						args,
					},
					manifest_set,
					share_set,
					enclave,
					patch_set,
				}))
			}
			ManifestVersion::V2 => {
				if self.patch_set.is_some() {
					return Err(ManifestBuilderError::V2DoesNotSupportPatchSet);
				}

				Ok(VersionedManifest::V2(ManifestV2 {
					version: ManifestVersion::V2,
					namespace,
					pivot: PivotConfigV2 {
						hash: pivot_hash,
						restart,
						bridge_config,
						debug_mode,
						args,
						env: self.pivot_env.unwrap_or_default(),
					},
					manifest_set,
					share_set,
					enclave,
					dns: self.dns,
				}))
			}
		}
	}
}

impl TryFrom<ManifestBuilder> for VersionedManifest {
	type Error = ManifestBuilderError;

	fn try_from(builder: ManifestBuilder) -> Result<Self, Self::Error> {
		builder.build()
	}
}
