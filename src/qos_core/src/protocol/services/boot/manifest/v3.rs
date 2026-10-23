//! Manifest V3 schema for OCI workloads.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::protocol::services::boot::{
	BridgeConfig, ManifestSet, Namespace, NitroConfig, ShareSet,
};

use super::{DnsConfig, ManifestVersion};

const MAX_WORKLOADS: usize = 16;
const MAX_VOLUMES: usize = 16;
const MAX_MOUNTS_PER_WORKLOAD: usize = 64;
const PCR_HEX_LEN: usize = 96;

/// The reserved implicit volume exposing the approved manifest, quorum key and
/// live ephemeral key. A manifest must not declare a volume with this name.
pub(crate) const QOS_VOLUME_NAME: &str = "qos";

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
		.any(|root| Self(String::from(*root)).overlaps(self))
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
		// Path::components would drop an interior `.`, which the string
		// comparisons of overlaps and parent_owned would then miss.
		if value.split('/').any(|part| part == "." || part == "..") {
			return Err("path must not contain . or .. components".into());
		}
		Ok(Self(value))
	}
}

/// The signed enclave-wide debug mode: what Manifest V2's pivot `debugMode`
/// is for its pivot, for every workload of the enclave. It changes neither
/// the PCRs nor how they are checked.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnclaveMode {
	/// Workload output goes to `/dev/null` (V2 `debugMode: false`).
	Attested,
	/// QOS reads and reprints every workload's output (V2 `debugMode: true`).
	Debug,
}

/// Serde for one Nitro PCR: exactly 96 lowercase hexadecimal characters.
///
/// Canonical JSON preserves string case, so accepting uppercase hex would let
/// two spellings of one PCR produce different manifest hashes.
mod pcr_hex {
	use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

	use super::PCR_HEX_LEN;

	pub(super) fn serialize<S: Serializer>(
		bytes: &[u8],
		serializer: S,
	) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&qos_hex::encode(bytes))
	}

	pub(super) fn deserialize<'de, D: Deserializer<'de>>(
		deserializer: D,
	) -> Result<Vec<u8>, D::Error> {
		let text = String::deserialize(deserializer)?;
		if text.len() != PCR_HEX_LEN
			|| !text.bytes().all(|byte| {
				byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
			}) {
			return Err(D::Error::custom(format!(
				"PCR must be {PCR_HEX_LEN} lowercase hexadecimal characters"
			)));
		}
		qos_hex::decode(&text).map_err(|error| {
			D::Error::custom(format!("invalid PCR: {error:?}"))
		})
	}
}

/// Nitro enclave settings in the tagged V3 form.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(
	tag = "type",
	rename_all = "camelCase",
	rename_all_fields = "camelCase",
	deny_unknown_fields
)]
pub enum EnclaveV3 {
	/// AWS Nitro enclave.
	#[serde(rename = "nitro")]
	Nitro {
		/// Signed expected identity: measured or debug.
		mode: EnclaveMode,
		/// Enclave image hash.
		#[serde(with = "pcr_hex")]
		pcr0: Vec<u8>,
		/// Kernel/bootstrap hash.
		#[serde(with = "pcr_hex")]
		pcr1: Vec<u8>,
		/// Application hash.
		#[serde(with = "pcr_hex")]
		pcr2: Vec<u8>,
		/// IAM role hash.
		#[serde(with = "pcr_hex")]
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
				..
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

	/// Return the signed enclave mode.
	#[must_use]
	pub fn mode(&self) -> EnclaveMode {
		match self {
			Self::Nitro { mode, .. } => *mode,
		}
	}
}

/// An approved OCI image reference.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(
	tag = "type",
	rename_all = "camelCase",
	rename_all_fields = "camelCase",
	deny_unknown_fields
)]
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
#[serde(rename_all = "lowercase")]
pub enum OciRestartPolicy {
	/// Do not restart after process exit.
	Never,
	/// Restart after every process exit until node shutdown.
	Always,
}

/// A device QOS can give a workload beyond the fixed runtime devices.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OciDevice {
	/// The Nitro Secure Module, which issues attestation documents.
	#[serde(rename = "nsm")]
	Nsm,
}

impl OciDevice {
	/// The device node in the enclave, and the only path a workload may
	/// mount it at.
	#[must_use]
	pub(crate) fn path(self) -> &'static str {
		match self {
			Self::Nsm => "/dev/nsm",
		}
	}
}

/// One declared attachment to an OCI workload.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(
	tag = "type",
	rename_all = "camelCase",
	rename_all_fields = "camelCase",
	deny_unknown_fields
)]
pub enum OciMount {
	/// A named top-level volume, or the reserved implicit `qos` volume.
	#[serde(rename = "volume")]
	Volume {
		/// Top-level volume name, or `qos`.
		source: OciName,
		/// Container target path.
		mount_path: OciPath,
		/// Whether the bind mount is read-only. A `qos` mount must be
		/// read-only.
		#[serde(default)]
		read_only: bool,
	},
	/// A device: this workload alone may open it.
	#[serde(rename = "device")]
	Device {
		/// The device.
		source: OciDevice,
		/// Container target path: the device's own path.
		mount_path: OciPath,
	},
}

impl OciMount {
	/// Return the container target path.
	#[must_use]
	pub fn mount_path(&self) -> &OciPath {
		match self {
			Self::Volume { mount_path, .. }
			| Self::Device { mount_path, .. } => mount_path,
		}
	}

	#[must_use]
	pub(crate) fn is_qos_volume(&self) -> bool {
		match self {
			Self::Volume { source, .. } => source.as_str() == QOS_VOLUME_NAME,
			Self::Device { .. } => false,
		}
	}
}

/// A Manifest V3 workload. Its name is its key in
/// [`ManifestV3::workloads`].
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(
	tag = "type",
	rename_all = "camelCase",
	rename_all_fields = "camelCase",
	deny_unknown_fields
)]
pub enum WorkloadV3 {
	/// An OCI container workload.
	#[serde(rename = "oci")]
	Oci {
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
#[serde(
	tag = "type",
	rename_all = "camelCase",
	rename_all_fields = "camelCase",
	deny_unknown_fields
)]
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
	/// Required OCI workloads keyed by their signed name. Canonical JSON sorts
	/// the keys, so member order does not affect the manifest hash.
	pub workloads: BTreeMap<OciName, WorkloadV3>,
	/// Optional named volumes.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub volumes: BTreeMap<OciName, VolumeV3>,
	/// Ingress into the workload group, in the Manifest V2 pivot
	/// `bridgeConfig` shape. Each `server` entry forwards host TCP `port`
	/// over VSOCK `port` to `127.0.0.1:port` in the workloads' shared network
	/// namespace. `client` (egress) entries are not supported yet.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub bridge_config: Vec<BridgeConfig>,
	/// Existing parent-QOS DNS configuration.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dns: Option<DnsConfig>,
}

impl ManifestV3 {
	/// Validate relationships that serde cannot express.
	///
	/// # Errors
	///
	/// Returns a validation message for invalid counts, a declared `qos`
	/// volume, a missing volume reference, a writable `qos` mount, a device
	/// mounted away from its own path, unsupported bridge entries, or
	/// overlapping/protected mount paths.
	pub fn validate(&self) -> Result<(), String> {
		self.validate_bridge_config()?;
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
		if self.volumes.keys().any(|name| name.as_str() == QOS_VOLUME_NAME) {
			return Err(format!(
				"volume name {QOS_VOLUME_NAME} is reserved for the implicit \
				 QOS volume"
			));
		}
		for (name, workload) in &self.workloads {
			if workload.mounts().len() > MAX_MOUNTS_PER_WORKLOAD {
				return Err(format!(
					"workload {} has more than {MAX_MOUNTS_PER_WORKLOAD} mounts",
					name.as_str()
				));
			}
			let mut paths: Vec<&OciPath> = Vec::new();
			for mount in workload.mounts() {
				let path = mount.mount_path();
				if paths.iter().any(|other| path.overlaps(other)) {
					return Err(format!(
						"overlapping workload mount path: {}",
						path.as_str()
					));
				}
				match mount {
					// A device goes at its own path in the runtime-owned
					// `/dev`, and nowhere else.
					OciMount::Device { source, .. } => {
						if path.as_str() != source.path() {
							return Err(format!(
								"device mount path must be {}",
								source.path()
							));
						}
					}
					OciMount::Volume { .. } if path.runtime_owned() => {
						return Err(format!(
							"runtime-owned mount path: {}",
							path.as_str()
						));
					}
					OciMount::Volume { read_only, .. }
						if mount.is_qos_volume() =>
					{
						if !read_only {
							return Err(format!(
								"{QOS_VOLUME_NAME} volume mount must be \
								 read-only"
							));
						}
					}
					OciMount::Volume { source, .. } => {
						if !self.volumes.contains_key(source) {
							return Err(format!(
								"undeclared volume: {}",
								source.as_str()
							));
						}
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

	fn validate_bridge_config(&self) -> Result<(), String> {
		let mut ports = HashSet::new();
		for bridge in &self.bridge_config {
			let BridgeConfig::Server { port, .. } = bridge else {
				return Err(
					"bridgeConfig client (egress) entries are not yet \
					 supported in manifest v3"
						.into(),
				);
			};
			if !ports.insert(*port) {
				return Err(format!(
					"duplicate bridgeConfig server port: {port}"
				));
			}
		}
		Ok(())
	}
}

/// Reject a JSON document that repeats a member name in any object.
///
/// Serde maps keep only the last of repeated members, so this must run on the
/// raw input before it is decoded: a decoded-map check cannot see the members
/// that were overwritten. Members spelled with different JSON escapes for the
/// same name (`"a"` and `"\u0061"`) are duplicates, because the parser
/// unescapes names before they are compared.
///
/// # Errors
///
/// Returns an error naming the repeated member, or the JSON syntax error.
pub(super) fn reject_duplicate_json_members(buf: &[u8]) -> Result<(), String> {
	let mut deserializer = serde_json::Deserializer::from_slice(buf);
	Distinct::deserialize(&mut deserializer).map_err(|e| e.to_string())?;
	deserializer.end().map_err(|e| e.to_string())
}

struct Distinct;

impl<'de> Deserialize<'de> for Distinct {
	fn deserialize<D: Deserializer<'de>>(
		deserializer: D,
	) -> Result<Self, D::Error> {
		deserializer.deserialize_any(DistinctVisitor)?;
		Ok(Self)
	}
}

struct DistinctVisitor;

impl<'de> serde::de::Visitor<'de> for DistinctVisitor {
	type Value = ();

	fn expecting(
		&self,
		formatter: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		formatter.write_str("any JSON value")
	}

	fn visit_bool<E>(self, _: bool) -> Result<(), E> {
		Ok(())
	}

	fn visit_i64<E>(self, _: i64) -> Result<(), E> {
		Ok(())
	}

	fn visit_u64<E>(self, _: u64) -> Result<(), E> {
		Ok(())
	}

	fn visit_f64<E>(self, _: f64) -> Result<(), E> {
		Ok(())
	}

	fn visit_str<E>(self, _: &str) -> Result<(), E> {
		Ok(())
	}

	fn visit_unit<E>(self) -> Result<(), E> {
		Ok(())
	}

	fn visit_seq<A: serde::de::SeqAccess<'de>>(
		self,
		mut seq: A,
	) -> Result<(), A::Error> {
		while seq.next_element::<Distinct>()?.is_some() {}
		Ok(())
	}

	fn visit_map<A: serde::de::MapAccess<'de>>(
		self,
		mut map: A,
	) -> Result<(), A::Error> {
		let mut seen = HashSet::new();
		while let Some(key) = map.next_key::<String>()? {
			if let Some(key) = seen.replace(key) {
				return Err(A::Error::custom(format!(
					"duplicate JSON member name: {key}"
				)));
			}
			map.next_value::<Distinct>()?;
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

/// A Manifest V3 with no approvers and one workload, `app`, that runs `image`.
#[cfg(test)]
pub(crate) fn minimal_manifest(image: &OciDigest) -> ManifestV3 {
	let pcr = "00".repeat(48);
	serde_json::from_value(serde_json::json!({
		"version": "v3",
		"namespace": {"name": "n", "nonce": 1, "quorumKey": "0a"},
		"manifestSet": {"threshold": 0, "members": []},
		"shareSet": {"threshold": 0, "members": []},
		"enclave": {
			"type": "nitro", "mode": "debug",
			"pcr0": pcr, "pcr1": pcr, "pcr2": pcr, "pcr3": pcr,
			"awsRootCertificate": "ff", "qosCommit": "c"
		},
		"workloads": {"app": {
			"type": "oci",
			"image": {"type": "ociManifest", "digest": image},
			"restart": "never",
		}},
	}))
	.unwrap()
}

#[cfg(test)]
mod tests {
	use super::*;

	const ZERO_PCR: &str = "000000000000000000000000000000000000000000000000\
	                        000000000000000000000000000000000000000000000000";

	/// A V3 document written as `docs/oci_support` specifies it: workloads
	/// keyed by name, and every multi-word field of a tagged object camelCase.
	const DOCUMENTED_JSON: &str = r#"{
		"version": "v3",
		"namespace": {"name": "golden", "nonce": 7, "quorumKey": "0a0b"},
		"manifestSet": {"threshold": 1, "members": [{"alias": "m", "pubKey": "01"}]},
		"shareSet": {"threshold": 1, "members": [{"alias": "s", "pubKey": "02"}]},
		"enclave": {
			"type": "nitro",
			"mode": "attested",
			"pcr0": "101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010",
			"pcr1": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
			"pcr2": "121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212",
			"pcr3": "131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313",
			"awsRootCertificate": "ff",
			"qosCommit": "abc123"
		},
		"volumes": {"shared": {"type": "tmpfs", "mountPath": "/mnt/qos/shared"}},
		"workloads": {
			"api": {
				"type": "oci",
				"image": {
					"type": "ociManifest",
					"digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
				},
				"restart": "always",
				"mounts": [
					{"type": "volume", "source": "shared", "mountPath": "/run/shared", "readOnly": true},
					{"type": "volume", "source": "qos", "mountPath": "/run/qos", "readOnly": true}
				]
			}
		}
	}"#;

	/// The canonical QOS JSON of [`DOCUMENTED_JSON`]: the signed bytes.
	const GOLDEN_CANONICAL: &str = concat!(
		r#"{"enclave":{"awsRootCertificate":"ff","#,
		r#""mode":"attested","#,
		r#""pcr0":"101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010","#,
		r#""pcr1":"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","#,
		r#""pcr2":"121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212","#,
		r#""pcr3":"131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313","#,
		r#""qosCommit":"abc123","type":"nitro"},"#,
		r#""manifestSet":{"members":[{"alias":"m","pubKey":"01"}],"threshold":"1"},"#,
		r#""namespace":{"name":"golden","nonce":"7","quorumKey":"0a0b"},"#,
		r#""shareSet":{"members":[{"alias":"s","pubKey":"02"}],"threshold":"1"},"#,
		r#""version":"v3","#,
		r#""volumes":{"shared":{"mountPath":"/mnt/qos/shared","type":"tmpfs"}},"#,
		r#""workloads":{"api":{"image":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","type":"ociManifest"},"#,
		r#""mounts":[{"mountPath":"/run/shared","readOnly":true,"source":"shared","type":"volume"},"#,
		r#"{"mountPath":"/run/qos","readOnly":true,"source":"qos","type":"volume"}],"#,
		r#""restart":"always","type":"oci"}}}"#,
	);

	fn documented() -> serde_json::Value {
		serde_json::from_str(DOCUMENTED_JSON).unwrap()
	}

	fn decode(value: &serde_json::Value) -> Result<ManifestV3, String> {
		let bytes = serde_json::to_vec(value).unwrap();
		let manifest =
			super::super::VersionedManifest::try_from_slice_compat(&bytes)
				.map_err(|error| error.to_string())?;
		match manifest {
			super::super::VersionedManifest::V3(manifest) => Ok(manifest),
			_ => Err("not v3".into()),
		}
	}

	fn api_mounts(value: &mut serde_json::Value) -> &mut serde_json::Value {
		&mut value["workloads"]["api"]["mounts"]
	}

	#[test]
	fn documented_camel_case_fields_are_the_signed_encoding() {
		let manifest: ManifestV3 =
			serde_json::from_str(DOCUMENTED_JSON).unwrap();
		manifest.validate().unwrap();
		assert_eq!(qos_json::to_string(&manifest).unwrap(), GOLDEN_CANONICAL);
		assert_eq!(
			serde_json::from_str::<ManifestV3>(GOLDEN_CANONICAL).unwrap(),
			manifest
		);
	}

	#[test]
	fn snake_case_fields_are_rejected() {
		serde_json::from_str::<ManifestV3>(DOCUMENTED_JSON).unwrap();
		for (camel, snake) in [
			("mountPath", "mount_path"),
			("readOnly", "read_only"),
			("awsRootCertificate", "aws_root_certificate"),
			("qosCommit", "qos_commit"),
		] {
			let json = DOCUMENTED_JSON.replace(camel, snake);
			assert!(
				serde_json::from_str::<ManifestV3>(&json).is_err(),
				"{snake} must not be accepted"
			);
		}
	}

	#[test]
	fn workload_order_does_not_change_the_hash_and_names_do() {
		let image = r#"{"type":"oci","restart":"never","image":{"type":"ociManifest","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}"#;
		let with = |members: &str| {
			let mut value = documented();
			value["workloads"] = serde_json::json!(0);
			let text = serde_json::to_string(&value).unwrap().replace(
				"\"workloads\":0",
				&format!("\"workloads\":{{{members}}}"),
			);
			serde_json::from_str::<ManifestV3>(&text).unwrap()
		};
		let hash = |manifest: &ManifestV3| {
			crate::protocol::services::boot::manifest::canonical_json_hash(
				manifest,
			)
		};
		let forward = with(&format!(r#""alpha":{image},"beta":{image}"#));
		let backward = with(&format!(r#""beta":{image},"alpha":{image}"#));
		let renamed = with(&format!(r#""alpha":{image},"gamma":{image}"#));
		assert_eq!(hash(&forward), hash(&backward));
		assert_eq!(
			qos_json::to_vec(&forward).unwrap(),
			qos_json::to_vec(&backward).unwrap()
		);
		assert_ne!(hash(&forward), hash(&renamed));
	}

	#[test]
	fn workload_name_field_and_bad_names_are_rejected() {
		let mut value = documented();
		value["workloads"]["api"]["name"] = "api".into();
		assert!(decode(&value).is_err());

		for bad in ["", "Api", "-a", "a-", "a_b", &"a".repeat(64)] {
			let mut value = documented();
			let api = value["workloads"]["api"].clone();
			value["workloads"] = serde_json::json!({ bad: api });
			assert!(decode(&value).is_err(), "name {bad:?}");
		}

		let mut value = documented();
		value["workloads"] = serde_json::json!({});
		assert!(decode(&value).is_err());
		value["workloads"] = serde_json::json!([]);
		assert!(decode(&value).is_err());
	}

	#[test]
	fn unsupported_workload_and_image_types_are_rejected() {
		let mut value = documented();
		value["workloads"]["api"]["type"] = "pivot".into();
		assert!(decode(&value).is_err());
		let mut value = documented();
		value["workloads"]["api"]["image"]["type"] = "ociIndex".into();
		assert!(decode(&value).is_err());
		let mut value = documented();
		value["workloads"]["api"]["extra"] = 1.into();
		assert!(decode(&value).is_err());
	}

	#[test]
	fn restart_values_are_lowercase() {
		for ok in ["never", "always"] {
			let mut value = documented();
			value["workloads"]["api"]["restart"] = ok.into();
			decode(&value).unwrap();
		}
		for bad in ["Never", "Always", "NEVER", "onFailure"] {
			let mut value = documented();
			value["workloads"]["api"]["restart"] = bad.into();
			assert!(decode(&value).is_err(), "{bad}");
		}
	}

	#[test]
	fn enclave_mode_is_required_and_signed() {
		let mut value = documented();
		value["enclave"].as_object_mut().unwrap().remove("mode");
		assert!(decode(&value).is_err());
		for bad in ["Attested", "production", ""] {
			let mut value = documented();
			value["enclave"]["mode"] = bad.into();
			assert!(decode(&value).is_err(), "{bad:?}");
		}
		let attested = decode(&documented()).unwrap();
		let mut value = documented();
		value["enclave"]["mode"] = "debug".into();
		for pcr in ["pcr0", "pcr1", "pcr2", "pcr3"] {
			value["enclave"][pcr] = ZERO_PCR.into();
		}
		let debug = decode(&value).unwrap();
		assert_eq!(attested.enclave.mode(), EnclaveMode::Attested);
		assert_eq!(debug.enclave.mode(), EnclaveMode::Debug);
		assert_ne!(
			qos_json::to_vec(&attested).unwrap(),
			qos_json::to_vec(&debug).unwrap()
		);
	}

	#[test]
	fn pcrs_are_96_lowercase_hex_characters() {
		for bad in [
			"10".to_string(),
			"1".repeat(95),
			"1".repeat(97),
			"A".repeat(96),
			format!("0x{}", "1".repeat(94)),
			"g".repeat(96),
		] {
			for pcr in ["pcr0", "pcr1", "pcr2", "pcr3"] {
				let mut value = documented();
				value["enclave"][pcr] = bad.clone().into();
				assert!(decode(&value).is_err(), "{pcr} {bad}");
			}
		}
	}

	#[test]
	fn the_mode_does_not_constrain_the_pcrs() {
		for mode in ["attested", "debug"] {
			let mut value = documented();
			value["enclave"]["mode"] = mode.into();
			decode(&value).unwrap();
			for pcr in ["pcr0", "pcr1", "pcr2", "pcr3"] {
				value["enclave"][pcr] = ZERO_PCR.into();
			}
			decode(&value).unwrap();
		}
	}

	#[test]
	fn the_nsm_mounts_at_its_own_path() {
		let nsm = serde_json::json!({
			"type": "device",
			"source": "nsm",
			"mountPath": "/dev/nsm"
		});
		let mut value = documented();
		api_mounts(&mut value).as_array_mut().unwrap().push(nsm.clone());
		let manifest = decode(&value).unwrap();
		let WorkloadV3::Oci { mounts, .. } =
			&manifest.workloads[&OciName::try_from("api".to_owned()).unwrap()];
		assert!(mounts.contains(&OciMount::Device {
			source: OciDevice::Nsm,
			mount_path: OciPath::try_from("/dev/nsm".to_owned()).unwrap(),
		}));
		for (field, bad) in [
			("mountPath", serde_json::json!("/mnt/nsm")),
			("mountPath", serde_json::json!("/dev/other")),
			("source", serde_json::json!("tpm")),
			("source", serde_json::json!("/dev/nsm")),
			("readOnly", serde_json::json!(true)),
		] {
			let mut mount = nsm.clone();
			mount[field] = bad.clone();
			let mut value = documented();
			api_mounts(&mut value).as_array_mut().unwrap().push(mount);
			assert!(decode(&value).is_err(), "{field} {bad}");
		}
		let mut value = documented();
		let mounts = api_mounts(&mut value).as_array_mut().unwrap();
		mounts.push(nsm.clone());
		mounts.push(nsm);
		let error = decode(&value).unwrap_err();
		assert!(error.contains("overlapping"), "{error}");
		let mut value = documented();
		api_mounts(&mut value)[0]["mountPath"] = "/dev/nsm".into();
		assert!(decode(&value).is_err());
	}

	#[test]
	fn file_mounts_are_gone() {
		let mut value = documented();
		api_mounts(&mut value).as_array_mut().unwrap().push(
			serde_json::json!({
				"type": "file",
				"source": "/qos.quorum.key",
				"mountPath": "/qos.quorum.key",
				"readOnly": true
			}),
		);
		assert!(decode(&value).is_err());
	}

	#[test]
	fn qos_volume_is_reserved_implicit_and_read_only() {
		let mut value = documented();
		value["volumes"]["qos"] =
			serde_json::json!({"type": "tmpfs", "mountPath": "/mnt/qos/own"});
		let error = decode(&value).unwrap_err();
		assert!(error.contains("reserved"), "{error}");

		let mut value = documented();
		api_mounts(&mut value)[1]["readOnly"] = false.into();
		let error = decode(&value).unwrap_err();
		assert!(error.contains("read-only"), "{error}");
		let mut value = documented();
		api_mounts(&mut value)[1].as_object_mut().unwrap().remove("readOnly");
		assert!(decode(&value).is_err());

		let mut value = documented();
		api_mounts(&mut value).as_array_mut().unwrap().remove(1);
		decode(&value).unwrap();
		let mut value = documented();
		value["volumes"] = serde_json::json!({});
		api_mounts(&mut value).as_array_mut().unwrap().remove(0);
		decode(&value).unwrap();

		let mut value = documented();
		api_mounts(&mut value)[0]["source"] = "other".into();
		let error = decode(&value).unwrap_err();
		assert!(error.contains("undeclared"), "{error}");
	}

	#[test]
	fn volume_and_mount_paths_are_checked() {
		for path in ["/proc/x", "/sys", "/dev/shm"] {
			let mut value = documented();
			api_mounts(&mut value)[0]["mountPath"] = path.into();
			assert!(decode(&value).is_err(), "{path}");
		}
		let mut value = documented();
		api_mounts(&mut value)[0]["mountPath"] = "/run".into();
		assert!(decode(&value).is_err(), "overlap with /run/qos");
		for path in [
			"/run/qos-oci",
			"/run/qos-oci/x",
			"/run",
			"/qos.manifest",
			"/qos.quorum.key/x",
			"/proc",
		] {
			let mut value = documented();
			value["volumes"]["shared"]["mountPath"] = path.into();
			assert!(decode(&value).is_err(), "{path}");
		}
		let mut value = documented();
		value["volumes"]["other"] =
			serde_json::json!({"type": "tmpfs", "mountPath": "/mnt/qos"});
		assert!(decode(&value).is_err(), "overlapping volumes");
	}

	#[test]
	fn bridge_config_has_the_v2_shape() {
		let mut value = documented();
		value["bridgeConfig"] = serde_json::json!([{"type": "server", "port": 3000, "host": "0.0.0.0"}]);
		let manifest = decode(&value).unwrap();
		assert_eq!(
			manifest.bridge_config,
			[BridgeConfig::Server { port: 3000, host: "0.0.0.0".into() }]
		);
		let canonical = qos_json::to_string(&manifest).unwrap();
		assert!(
			canonical.contains(
				r#""bridgeConfig":[{"host":"0.0.0.0","port":"3000","type":"server"}]"#
			),
			"{canonical}"
		);
		let versioned = super::super::VersionedManifest::V3(manifest);
		assert_eq!(
			versioned.bridge_config(),
			[BridgeConfig::Server { port: 3000, host: "0.0.0.0".into() }]
		);
		value["bridgeConfig"] = serde_json::json!([]);
		assert_eq!(
			qos_json::to_string(&decode(&value).unwrap()).unwrap(),
			GOLDEN_CANONICAL
		);
	}

	#[test]
	fn bridge_config_rejects_egress_and_port_clashes() {
		let mut value = documented();
		value["bridgeConfig"] = serde_json::json!([
			{"type": "client", "port": 443, "host": "example.com"}
		]);
		let error = decode(&value).unwrap_err();
		assert!(error.contains("not yet supported"), "{error}");
		value["bridgeConfig"] = serde_json::json!([
			{"type": "server", "port": 3000, "host": "0.0.0.0"},
			{"type": "server", "port": 3000, "host": "127.0.0.1"}
		]);
		let error = decode(&value).unwrap_err();
		assert!(error.contains("duplicate"), "{error}");
	}

	#[test]
	fn duplicate_json_members_are_rejected_at_every_level() {
		reject_duplicate_json_members(DOCUMENTED_JSON.as_bytes()).unwrap();
		for bad in [
			r#"{"a":1,"a":2}"#,
			r#"{"a":{"b":1,"b":2}}"#,
			r#"[{"a":1},{"b":[{"c":1,"c":1}]}]"#,
			// Different escapes of the same name.
			r#"{"a":1,"\u0061":2}"#,
			r#"{"\u0061b":1,"a\u0062":2}"#,
		] {
			let error =
				reject_duplicate_json_members(bad.as_bytes()).unwrap_err();
			assert!(error.contains("duplicate"), "{bad}: {error}");
		}
		assert!(reject_duplicate_json_members(br#"{"a":1} x"#).is_err());
		reject_duplicate_json_members(br#"{"a":{"x":1},"b":{"x":1}}"#).unwrap();

		let duplicated_workload = DOCUMENTED_JSON.replacen(
			r#""workloads": {"#,
			r#""workloads": {"api": {"type": "oci", "image": {"type": "ociManifest", "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}, "restart": "never"},"#,
			1,
		);
		// serde would silently keep the last `api`.
		assert!(
			serde_json::from_str::<ManifestV3>(&duplicated_workload).is_ok()
		);
		let error = super::super::VersionedManifest::try_from_slice_compat(
			duplicated_workload.as_bytes(),
		)
		.unwrap_err();
		assert!(error.to_string().contains("duplicate"), "{error}");
		let envelope = format!(
			r#"{{"manifest":{duplicated_workload},"manifestSetApprovals":[],"shareSetApprovals":[]}}"#
		);
		let error =
			super::super::VersionedManifestEnvelope::try_from_slice_compat(
				envelope.as_bytes(),
			)
			.unwrap_err();
		assert!(error.to_string().contains("duplicate"), "{error}");
		super::super::VersionedManifestEnvelope::try_from_slice_compat(
			format!(
				r#"{{"manifest":{DOCUMENTED_JSON},"manifestSetApprovals":[],"shareSetApprovals":[]}}"#
			)
			.as_bytes(),
		)
		.unwrap();
	}

	#[test]
	fn newtypes_reject_noncanonical_identity_and_paths() {
		assert!(OciName::try_from("Bad_Name".to_string()).is_err());
		assert!(
			OciDigest::try_from(format!("sha256:{}", "A".repeat(64))).is_err()
		);
		assert!(OciPath::try_from("/run/../key".to_string()).is_err());
		assert!(OciPath::try_from("/run/./qos-oci".to_string()).is_err());
		assert!(OciPath::try_from("/./dev".to_string()).is_err());
		assert!(OciPath::try_from("/".to_string()).is_err());
	}
}
