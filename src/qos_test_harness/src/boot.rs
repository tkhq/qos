//! In-memory boot material and policy types.

use std::path::PathBuf;

/// Fixture inputs used by `qos_client` to approve and boot a test manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootClientFixture {
	/// Fixture files consumed by `qos_client` while it approves and boots the manifest.
	pub material: BootMaterial,
	/// Fixture users that approve the manifest and submit their encrypted shares.
	pub approving_users: Vec<ApprovingUserMaterial>,
	/// Pass `--unsafe-skip-attestation` to the fixture-only `qos_client` commands.
	pub unsafe_skip_attestation: bool,
	/// Pass `--unsafe-auto-confirm` to the fixture-only `qos_client` commands.
	pub unsafe_auto_confirm: bool,
}

/// In-memory boot material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootMaterial {
	/// Bytes used by `qos_client` to derive PCR3 while approving and booting.
	pub pcr3_preimage: Vec<u8>,
	/// Release artifacts whose PCR values are checked during manifest approval.
	pub qos_release: QosReleaseMaterial,
	/// Public keys and threshold used to validate manifest approvals.
	pub manifest_set: KeySetMaterial,
	/// Public keys and threshold used to validate encrypted share approvals.
	pub share_set: KeySetMaterial,
	/// Namespace quorum public key checked against the built manifest.
	pub quorum_key: Vec<u8>,
}

/// In-memory QOS release material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosReleaseMaterial {
	/// Files staged as the release-artifact directory expected by `qos_client`.
	pub files: Vec<MaterialFile>,
}

/// In-memory key set material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySetMaterial {
	/// Key and threshold files staged as a `qos_client` approval-set directory.
	pub files: Vec<MaterialFile>,
}

/// In-memory material file with a bundle-relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialFile {
	/// Relative destination below the staged material directory; cannot escape it.
	pub relative_path: PathBuf,
	/// Bytes written at `relative_path`.
	pub contents: Vec<u8>,
}

/// User material used to approve manifests and post shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovingUserMaterial {
	/// Alias matching a member of the fixture manifest approval set.
	pub alias: String,
	/// Private key bytes used to sign the manifest approval and re-encrypt the share.
	pub secret: Vec<u8>,
	/// Encrypted share bytes submitted after the guest attestation document is available.
	pub share: Vec<u8>,
}
