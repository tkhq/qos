//! Verification of host-supplied OCI image-layout archives.

use std::{
	collections::{BTreeMap, HashSet},
	io::{Cursor, Read},
	path::{Component, Path},
};

use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::protocol::{
	ProtocolError, oci::MAX_OCI_LAYOUT_ARCHIVE_BYTES, services::boot::OciDigest,
};

const OCI_LAYOUT: &str = "oci-layout";
const OCI_INDEX: &str = "index.json";
const IMAGE_MANIFEST_MEDIA_TYPE: &str =
	"application/vnd.oci.image.manifest.v1+json";
const IMAGE_CONFIG_MEDIA_TYPE: &str =
	"application/vnd.oci.image.config.v1+json";
const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const LAYER_GZIP_MEDIA_TYPE: &str =
	"application/vnd.oci.image.layer.v1.tar+gzip";
const LAYER_ZSTD_MEDIA_TYPE: &str =
	"application/vnd.oci.image.layer.v1.tar+zstd";
const MAX_LAYOUT_ENTRIES: usize = 16_384;
const MAX_LAYOUT_PATH_BYTES: usize = 4_096;
const MAX_LAYER_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_IMAGE_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LAYER_COMPRESSION_RATIO: u64 = 1_024;

fn invalid(message: impl Into<String>) -> ProtocolError {
	ProtocolError::InvalidOci(message.into())
}

/// Compression applied to a verified OCI layer blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerCompression {
	/// Uncompressed tar.
	Plain,
	/// Gzip-compressed tar.
	Gzip,
	/// Zstandard-compressed tar.
	Zstd,
}

/// One verified layer in application order.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedLayer {
	/// Supported compression format.
	pub compression: LayerCompression,
	pub(crate) blob: Vec<u8>,
}

/// Process defaults derived only from the verified image configuration.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedProcess {
	/// Image entrypoint.
	pub entrypoint: Vec<String>,
	/// Image command.
	pub cmd: Vec<String>,
	/// Raw `NAME=value` entries.
	pub env: Vec<String>,
	/// OCI user expression.
	pub user: String,
	/// Absolute container working directory.
	pub working_dir: String,
	/// Optional image stop signal.
	pub stop_signal: Option<String>,
}

/// Reachable, digest-verified image content retained for bundle creation.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedOciImage {
	/// Verified layers in application order.
	pub layers: Vec<VerifiedLayer>,
	/// Verified process defaults.
	pub process: VerifiedProcess,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
	media_type: String,
	digest: OciDigest,
	size: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageIndex {
	schema_version: u32,
	manifests: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageManifest {
	schema_version: u32,
	media_type: String,
	config: Descriptor,
	layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct ImageLayout {
	#[serde(rename = "imageLayoutVersion")]
	version: String,
}

#[derive(Deserialize)]
struct RootFs {
	#[serde(rename = "type")]
	type_name: String,
	diff_ids: Vec<OciDigest>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageProcess {
	#[serde(default)]
	entrypoint: Vec<String>,
	#[serde(default)]
	cmd: Vec<String>,
	#[serde(default)]
	env: Vec<String>,
	#[serde(default)]
	user: String,
	#[serde(default)]
	working_dir: String,
	stop_signal: Option<String>,
}

#[derive(Deserialize)]
struct ImageConfiguration {
	architecture: String,
	os: String,
	rootfs: RootFs,
	config: Option<ImageProcess>,
}

/// Verify an OCI image-layout tar against its signed root digest.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidOci`] for malformed layouts, unsafe tar
/// entries, unsupported media/platform values, or any digest/size mismatch.
pub fn verify_oci_layout(
	expected: &OciDigest,
	archive: &[u8],
) -> Result<VerifiedOciImage, ProtocolError> {
	let files = read_layout(archive)?;
	let layout: ImageLayout = decode_required(&files, OCI_LAYOUT)?;
	if layout.version != "1.0.0" {
		return Err(invalid("unsupported OCI image-layout version"));
	}
	let index: ImageIndex = decode_required(&files, OCI_INDEX)?;
	let root_descriptor = index.manifests.iter().find(|descriptor| {
		&descriptor.digest == expected
			&& descriptor.media_type == IMAGE_MANIFEST_MEDIA_TYPE
	});
	if index.schema_version != 2 {
		return Err(invalid("index.json does not select the signed manifest"));
	}
	let root_descriptor = root_descriptor.ok_or_else(|| {
		invalid("index.json does not select the signed manifest")
	})?;
	let manifest_bytes = verified_descriptor(&files, root_descriptor)?;
	let manifest: ImageManifest = serde_json::from_slice(manifest_bytes)
		.map_err(|_| invalid("root descriptor is not an OCI image manifest"))?;
	if manifest.schema_version != 2
		|| manifest.media_type != IMAGE_MANIFEST_MEDIA_TYPE
		|| manifest.config.media_type != IMAGE_CONFIG_MEDIA_TYPE
	{
		return Err(invalid("unsupported OCI manifest or config media type"));
	}
	let config_bytes = verified_descriptor(&files, &manifest.config)?;
	let config: ImageConfiguration = serde_json::from_slice(config_bytes)
		.map_err(|_| invalid("invalid OCI image configuration"))?;
	validate_platform_and_rootfs(&config)?;
	if config.rootfs.diff_ids.len() != manifest.layers.len() {
		return Err(invalid("layer and DiffID counts differ"));
	}

	let mut total_unpacked = 0_u64;
	let mut layers = Vec::with_capacity(manifest.layers.len());
	for (descriptor, diff_id) in
		manifest.layers.iter().zip(config.rootfs.diff_ids)
	{
		let compression = match descriptor.media_type.as_str() {
			LAYER_MEDIA_TYPE => LayerCompression::Plain,
			LAYER_GZIP_MEDIA_TYPE => LayerCompression::Gzip,
			LAYER_ZSTD_MEDIA_TYPE => LayerCompression::Zstd,
			_ => return Err(invalid("unsupported OCI layer media type")),
		};
		let blob = verified_descriptor(&files, descriptor)?;
		let unpacked = decompress_layer(blob, compression)?;
		total_unpacked = total_unpacked
			.checked_add(unpacked.len() as u64)
			.ok_or_else(|| invalid("unpacked image size overflow"))?;
		if total_unpacked > MAX_IMAGE_UNPACKED_BYTES {
			return Err(invalid("unpacked image exceeds limit"));
		}
		if digest(&unpacked) != diff_id {
			return Err(invalid("OCI layer DiffID mismatch"));
		}
		layers.push(VerifiedLayer { compression, blob: blob.to_vec() });
	}

	let process = config.config.unwrap_or_default();
	Ok(VerifiedOciImage {
		layers,
		process: VerifiedProcess {
			entrypoint: process.entrypoint,
			cmd: process.cmd,
			env: process.env,
			user: process.user,
			working_dir: if process.working_dir.is_empty() {
				"/".into()
			} else {
				process.working_dir
			},
			stop_signal: process.stop_signal,
		},
	})
}

fn read_layout(
	archive: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, ProtocolError> {
	let mut tar = tar::Archive::new(Cursor::new(archive));
	let entries =
		tar.entries().map_err(|_| invalid("invalid OCI layout tar"))?;
	let mut files = BTreeMap::new();
	let mut paths = HashSet::new();
	let mut entry_count = 0_usize;
	let mut content_bytes = 0_u64;
	for entry in entries {
		entry_count += 1;
		if entry_count > MAX_LAYOUT_ENTRIES {
			return Err(invalid("OCI layout entry-count limit exceeded"));
		}
		let mut entry =
			entry.map_err(|_| invalid("invalid OCI layout entry"))?;
		let path =
			entry.path().map_err(|_| invalid("invalid OCI layout path"))?;
		let path = normalized_path(&path)?;
		if !paths.insert(path.clone()) {
			return Err(invalid("duplicate OCI layout path"));
		}
		let entry_type = entry.header().entry_type();
		if entry_type.is_dir() {
			continue;
		}
		if !entry_type.is_file() {
			return Err(invalid("OCI layout contains a non-regular entry"));
		}
		let declared = entry
			.header()
			.size()
			.map_err(|_| invalid("invalid OCI layout file size"))?;
		if declared > archive.len() as u64 {
			return Err(invalid("OCI layout file exceeds archive size"));
		}
		content_bytes = content_bytes
			.checked_add(declared)
			.ok_or_else(|| invalid("OCI layout content size overflow"))?;
		if content_bytes > MAX_OCI_LAYOUT_ARCHIVE_BYTES as u64 {
			return Err(invalid("OCI layout content exceeds limit"));
		}
		let capacity = usize::try_from(declared)
			.map_err(|_| invalid("OCI layout file exceeds address space"))?;
		let mut bytes = Vec::with_capacity(capacity);
		entry
			.read_to_end(&mut bytes)
			.map_err(|_| invalid("failed to read OCI layout file"))?;
		if bytes.len() as u64 != declared {
			return Err(invalid("OCI layout file size mismatch"));
		}
		files.insert(path, bytes);
	}
	Ok(files)
}

fn normalized_path(path: &Path) -> Result<String, ProtocolError> {
	if path.is_absolute() || path.as_os_str().len() > MAX_LAYOUT_PATH_BYTES {
		return Err(invalid("OCI layout path is not safe"));
	}
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::Normal(part) => parts.push(
				part.to_str()
					.ok_or_else(|| invalid("OCI layout path is not UTF-8"))?,
			),
			_ => return Err(invalid("OCI layout path is not normalized")),
		}
	}
	if parts.is_empty() {
		return Err(invalid("OCI layout path is empty"));
	}
	Ok(parts.join("/"))
}

fn decode_required<T: for<'de> Deserialize<'de>>(
	files: &BTreeMap<String, Vec<u8>>,
	path: &str,
) -> Result<T, ProtocolError> {
	serde_json::from_slice(
		files.get(path).ok_or_else(|| invalid(format!("missing {path}")))?,
	)
	.map_err(|_| invalid(format!("invalid {path}")))
}

fn verified_descriptor<'a>(
	files: &'a BTreeMap<String, Vec<u8>>,
	descriptor: &Descriptor,
) -> Result<&'a [u8], ProtocolError> {
	let path = format!("blobs/sha256/{}", descriptor.digest.hex());
	let bytes =
		files.get(&path).ok_or_else(|| invalid("required OCI blob missing"))?;
	if descriptor.size != bytes.len() as u64 {
		return Err(invalid("OCI descriptor size mismatch"));
	}
	if digest(bytes) != descriptor.digest {
		return Err(invalid("OCI blob digest mismatch"));
	}
	Ok(bytes)
}

fn digest(bytes: &[u8]) -> OciDigest {
	format!("sha256:{}", qos_hex::encode(&qos_crypto::sha_256(bytes)))
		.try_into()
		.expect("SHA-256 always produces a valid OCI digest")
}

fn validate_platform_and_rootfs(
	config: &ImageConfiguration,
) -> Result<(), ProtocolError> {
	let architecture = match std::env::consts::ARCH {
		"x86_64" => "amd64",
		"aarch64" => "arm64",
		_ => return Err(invalid("unsupported enclave architecture")),
	};
	if config.os != "linux" || config.architecture != architecture {
		return Err(invalid("OCI image platform does not match the enclave"));
	}
	if config.rootfs.type_name != "layers" {
		return Err(invalid("OCI rootfs type must be layers"));
	}
	Ok(())
}

/// Decompress one verified layer with a fixed expansion limit.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidOci`] when the compressed stream is
/// malformed or expands beyond the configured limit.
pub fn decompress_layer(
	bytes: &[u8],
	compression: LayerCompression,
) -> Result<Vec<u8>, ProtocolError> {
	let reader: Box<dyn Read> = match compression {
		LayerCompression::Plain => Box::new(Cursor::new(bytes)),
		LayerCompression::Gzip => Box::new(GzDecoder::new(bytes)),
		LayerCompression::Zstd => Box::new(
			zstd::stream::read::Decoder::new(bytes)
				.map_err(|_| invalid("invalid zstd OCI layer"))?,
		),
	};
	let mut output = Vec::new();
	reader
		.take(MAX_LAYER_UNPACKED_BYTES + 1)
		.read_to_end(&mut output)
		.map_err(|_| invalid("failed to decompress OCI layer"))?;
	if output.len() as u64 > MAX_LAYER_UNPACKED_BYTES {
		return Err(invalid("OCI layer expansion limit exceeded"));
	}
	if compression != LayerCompression::Plain
		&& output.len() as u64
			> (bytes.len() as u64).saturating_mul(MAX_LAYER_COMPRESSION_RATIO)
	{
		return Err(invalid("OCI layer compression ratio exceeds limit"));
	}
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn layout_limit_counts_directories() {
		let mut archive = Vec::new();
		{
			let mut builder = tar::Builder::new(&mut archive);
			for index in 0..=MAX_LAYOUT_ENTRIES {
				let mut header = tar::Header::new_ustar();
				header.set_entry_type(tar::EntryType::Directory);
				header.set_mode(0o755);
				header.set_size(0);
				header.set_cksum();
				builder
					.append_data(&mut header, format!("d/{index}"), &[][..])
					.unwrap();
			}
			builder.finish().unwrap();
		}
		assert!(read_layout(&archive).is_err());
	}

	#[test]
	fn decompression_ratio_is_bounded() {
		let expanded = vec![0_u8; 2 * 1024 * 1024];
		let compressed =
			zstd::stream::encode_all(Cursor::new(expanded), 1).unwrap();
		assert!(decompress_layer(&compressed, LayerCompression::Zstd).is_err());
	}
}
