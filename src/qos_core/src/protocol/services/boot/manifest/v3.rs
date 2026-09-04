//! Manifest V3 schema for OCI workloads.

use std::{
	collections::{BTreeMap, HashSet},
	path::Path,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::protocol::services::boot::{
	ManifestSet, Namespace, NitroConfig, ShareSet,
};

use super::{DnsConfig, ManifestVersion};

const MAX_WORKLOADS: usize = 16;
const MAX_VOLUMES: usize = 16;
const MAX_MOUNTS_PER_WORKLOAD: usize = 64;

macro_rules! validated_string_wire {
	($name:ident, $valid_len:expr, $length_error:literal) => {
		impl borsh::BorshDeserialize for $name {
			fn deserialize_reader<R: borsh::io::Read>(
				reader: &mut R,
			) -> borsh::io::Result<Self> {
				let len = u32::deserialize_reader(reader)? as usize;
				if !($valid_len)(len) {
					return Err(borsh::io::Error::new(
						borsh::io::ErrorKind::InvalidData,
						$length_error,
					));
				}
				let mut bytes = vec![0; len];
				reader.read_exact(&mut bytes)?;
				String::from_utf8(bytes)
					.map_err(borsh::io::Error::other)?
					.try_into()
					.map_err(borsh::io::Error::other)
			}
		}
	};
}

/// A validated workload or volume name.
#[derive(
	Debug,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Hash,
	Clone,
	Serialize,
	Deserialize,
	borsh::BorshSerialize,
)]
#[serde(try_from = "String")]
pub struct OciName(String);

impl OciName {
	/// Return the validated name.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl TryFrom<String> for OciName {
	type Error = String;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		let bytes = value.as_bytes();
		let edge =
			|byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
		if !(1..=63).contains(&bytes.len())
			|| !bytes.first().is_some_and(|byte| edge(*byte))
			|| !bytes.last().is_some_and(|byte| edge(*byte))
			|| !bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
		{
			return Err(
				"name must be a 1-63 character lowercase DNS label".into()
			);
		}
		Ok(Self(value))
	}
}

validated_string_wire!(
	OciName,
	|len| (1..=63).contains(&len),
	"invalid OCI name length"
);

/// A validated SHA-256 OCI descriptor digest.
#[derive(
	Debug,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Hash,
	Clone,
	Serialize,
	Deserialize,
	borsh::BorshSerialize,
)]
#[serde(try_from = "String")]
pub struct OciDigest(String);

impl OciDigest {
	/// Return the canonical digest text.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Return the hexadecimal portion of the digest.
	#[must_use]
	pub fn hex(&self) -> &str {
		&self.0[7..]
	}
}

impl TryFrom<String> for OciDigest {
	type Error = String;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		let Some(hex) = value.strip_prefix("sha256:") else {
			return Err("OCI digest must start with sha256:".into());
		};
		if hex.len() != 64
			|| !hex.bytes().all(|byte| {
				byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
			}) {
			return Err(
				"OCI digest must contain 64 lowercase hexadecimal characters"
					.into(),
			);
		}
		Ok(Self(value))
	}
}

validated_string_wire!(OciDigest, |len| len == 71, "invalid OCI digest length");

/// An absolute normalized non-root path.
#[derive(
	Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize,
)]
#[serde(try_from = "String")]
pub struct OciPath(String);

impl OciPath {
	/// Return the validated path.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	fn overlaps(&self, other: &Self) -> bool {
		self == other
			|| self
				.0
				.strip_prefix(&other.0)
				.is_some_and(|tail| tail.starts_with('/'))
			|| other
				.0
				.strip_prefix(&self.0)
				.is_some_and(|tail| tail.starts_with('/'))
	}

	fn runtime_owned(&self) -> bool {
		["/proc", "/sys", "/dev"].iter().any(|root| {
			self.0 == *root
				|| self
					.0
					.strip_prefix(root)
					.is_some_and(|tail| tail.starts_with('/'))
		})
	}

	fn parent_owned(&self) -> bool {
		[
			"/run/qos-oci",
			"/qos.quorum.key",
			"/qos.ephemeral.key",
			"/qos.manifest",
		]
		.iter()
		.any(|root| {
			self.0 == *root
				|| self
					.0
					.strip_prefix(root)
					.is_some_and(|tail| tail.starts_with('/'))
		})
	}
}

impl TryFrom<String> for OciPath {
	type Error = String;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		if value == "/"
			|| !value.starts_with('/')
			|| value.contains('\0')
			|| value.contains("//")
			|| value.ends_with('/')
		{
			return Err(
				"path must be absolute, normalized, and non-root".into()
			);
		}
		if Path::new(&value).components().any(|component| {
			matches!(
				component,
				std::path::Component::CurDir | std::path::Component::ParentDir
			)
		}) {
			return Err("path must not contain . or .. components".into());
		}
		Ok(Self(value))
	}
}

/// Nitro enclave settings in the tagged V3 form.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum EnclaveV3 {
	/// AWS Nitro enclave.
	#[serde(rename = "nitro")]
	Nitro {
		/// Enclave image hash.
		#[serde(with = "qos_hex::serde")]
		pcr0: Vec<u8>,
		/// Kernel/bootstrap hash.
		#[serde(with = "qos_hex::serde")]
		pcr1: Vec<u8>,
		/// Application hash.
		#[serde(with = "qos_hex::serde")]
		pcr2: Vec<u8>,
		/// IAM role hash.
		#[serde(with = "qos_hex::serde")]
		pcr3: Vec<u8>,
		/// AWS root certificate.
		#[serde(with = "qos_hex::serde")]
		aws_root_certificate: Vec<u8>,
		/// QOS source revision.
		qos_commit: String,
	},
}

impl EnclaveV3 {
	/// Convert the tagged V3 representation to the existing Nitro settings.
	#[must_use]
	pub fn nitro_config(&self) -> NitroConfig {
		match self {
			Self::Nitro {
				pcr0,
				pcr1,
				pcr2,
				pcr3,
				aws_root_certificate,
				qos_commit,
			} => NitroConfig {
				pcr0: pcr0.clone(),
				pcr1: pcr1.clone(),
				pcr2: pcr2.clone(),
				pcr3: pcr3.clone(),
				aws_root_certificate: aws_root_certificate.clone(),
				qos_commit: qos_commit.clone(),
			},
		}
	}
}

/// An approved OCI image reference.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum OciImageRef {
	/// A platform-specific OCI image manifest.
	#[serde(rename = "ociManifest")]
	OciManifest {
		/// Signed manifest digest.
		digest: OciDigest,
	},
}

impl OciImageRef {
	/// Return the approved digest.
	#[must_use]
	pub fn digest(&self) -> &OciDigest {
		match self {
			Self::OciManifest { digest } => digest,
		}
	}
}

/// OCI workload restart policy.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OciRestartPolicy {
	/// Do not restart after process exit.
	Never,
	/// Restart after every process exit until node shutdown.
	Always,
}

/// One declared attachment to an OCI workload.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum OciMount {
	/// A named top-level volume.
	#[serde(rename = "volume")]
	Volume {
		/// Top-level volume name.
		source: OciName,
		/// Container target path.
		mount_path: OciPath,
		/// Whether the bind mount is read-only.
		#[serde(default)]
		read_only: bool,
	},
	/// An approved regular parent-QOS file.
	#[serde(rename = "file")]
	File {
		/// Parent source path.
		source: OciPath,
		/// Container target path.
		mount_path: OciPath,
		/// Whether the bind mount is read-only.
		#[serde(default)]
		read_only: bool,
	},
}

impl OciMount {
	/// Return the container target path.
	#[must_use]
	pub fn mount_path(&self) -> &OciPath {
		match self {
			Self::Volume { mount_path, .. } | Self::File { mount_path, .. } => {
				mount_path
			}
		}
	}
}

/// A Manifest V3 workload.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum WorkloadV3 {
	/// An OCI container workload.
	#[serde(rename = "oci")]
	Oci {
		/// Stable workload identity.
		name: OciName,
		/// Approved image.
		image: OciImageRef,
		/// Signed restart policy.
		restart: OciRestartPolicy,
		/// Explicit workload attachments.
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		mounts: Vec<OciMount>,
	},
}

impl WorkloadV3 {
	/// Return the stable workload name.
	#[must_use]
	pub fn name(&self) -> &OciName {
		match self {
			Self::Oci { name, .. } => name,
		}
	}

	/// Return the approved image.
	#[must_use]
	pub fn image(&self) -> &OciImageRef {
		match self {
			Self::Oci { image, .. } => image,
		}
	}

	fn mounts(&self) -> &[OciMount] {
		match self {
			Self::Oci { mounts, .. } => mounts,
		}
	}
}

/// A named top-level volume declaration.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum VolumeV3 {
	/// Volatile tmpfs storage.
	#[serde(rename = "tmpfs")]
	Tmpfs {
		/// Parent-QOS mount path.
		mount_path: OciPath,
	},
}

impl VolumeV3 {
	fn mount_path(&self) -> &OciPath {
		match self {
			Self::Tmpfs { mount_path } => mount_path,
		}
	}
}

/// Explicitly versioned OCI manifest.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestV3 {
	/// Manifest schema version.
	#[serde(deserialize_with = "deserialize_v3_version")]
	pub version: ManifestVersion,
	/// Existing QOS namespace.
	pub namespace: Namespace,
	/// Manifest approvers.
	pub manifest_set: ManifestSet,
	/// Share providers.
	pub share_set: ShareSet,
	/// Tagged enclave configuration.
	pub enclave: EnclaveV3,
	/// Required OCI workloads.
	pub workloads: Vec<WorkloadV3>,
	/// Optional named volumes.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub volumes: BTreeMap<OciName, VolumeV3>,
	/// Existing parent-QOS DNS configuration.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dns: Option<DnsConfig>,
}

impl ManifestV3 {
	/// Validate relationships that serde cannot express.
	///
	/// # Errors
	///
	/// Returns a validation message for invalid counts, duplicate names,
	/// missing volume references, or overlapping/protected mount paths.
	pub fn validate(&self) -> Result<(), String> {
		if !(1..=MAX_WORKLOADS).contains(&self.workloads.len()) {
			return Err(format!(
				"workloads must contain 1-{MAX_WORKLOADS} entries"
			));
		}
		if self.volumes.len() > MAX_VOLUMES {
			return Err(format!(
				"volumes must contain at most {MAX_VOLUMES} entries"
			));
		}
		let mut names = HashSet::new();
		for workload in &self.workloads {
			if workload.mounts().len() > MAX_MOUNTS_PER_WORKLOAD {
				return Err(format!(
					"workload {} has more than {MAX_MOUNTS_PER_WORKLOAD} mounts",
					workload.name().as_str()
				));
			}
			if !names.insert(workload.name()) {
				return Err(format!(
					"duplicate workload name: {}",
					workload.name().as_str()
				));
			}
			let mut paths: Vec<&OciPath> = Vec::new();
			for mount in workload.mounts() {
				let path = mount.mount_path();
				if path.runtime_owned() {
					return Err(format!(
						"runtime-owned mount path: {}",
						path.as_str()
					));
				}
				if paths.iter().any(|other| path.overlaps(other)) {
					return Err(format!(
						"overlapping workload mount path: {}",
						path.as_str()
					));
				}
				if let OciMount::Volume { source, .. } = mount
					&& !self.volumes.contains_key(source)
				{
					return Err(format!(
						"undeclared volume: {}",
						source.as_str()
					));
				}
				if let OciMount::File { source, read_only, .. } = mount {
					if !matches!(
						source.as_str(),
						"/qos.quorum.key"
							| "/qos.ephemeral.key"
							| "/qos.manifest"
					) {
						return Err(format!(
							"unsupported file source: {}",
							source.as_str()
						));
					}
					if !read_only {
						return Err(format!(
							"protected file must be read-only: {}",
							source.as_str()
						));
					}
				}
				paths.push(path);
			}
		}
		let paths: Vec<_> =
			self.volumes.values().map(VolumeV3::mount_path).collect();
		for (index, path) in paths.iter().enumerate() {
			if path.runtime_owned() || path.parent_owned() {
				return Err(format!(
					"parent-owned top-level volume path: {}",
					path.as_str()
				));
			}
			if paths[index + 1..].iter().any(|other| path.overlaps(other)) {
				return Err(format!(
					"overlapping top-level volume path: {}",
					path.as_str()
				));
			}
		}
		Ok(())
	}
}

fn deserialize_v3_version<'de, D: Deserializer<'de>>(
	deserializer: D,
) -> Result<ManifestVersion, D::Error> {
	match ManifestVersion::deserialize(deserializer)? {
		ManifestVersion::V3 => Ok(ManifestVersion::V3),
		other => Err(D::Error::custom(format!(
			"manifest v3 requires version v3, got {other:?}"
		))),
	}
}

/// Signed Manifest V3 envelope.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEnvelopeV3 {
	/// Signed manifest.
	pub manifest: ManifestV3,
	/// Manifest-set signatures.
	pub manifest_set_approvals: Vec<crate::protocol::services::boot::Approval>,
	/// Share-set signatures.
	pub share_set_approvals: Vec<crate::protocol::services::boot::Approval>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn newtypes_reject_noncanonical_identity_and_paths() {
		assert!(OciName::try_from("Bad_Name".to_string()).is_err());
		assert!(
			OciDigest::try_from(format!("sha256:{}", "A".repeat(64))).is_err()
		);
		assert!(OciPath::try_from("/run/../key".to_string()).is_err());
		assert!(OciPath::try_from("/".to_string()).is_err());
	}
}
