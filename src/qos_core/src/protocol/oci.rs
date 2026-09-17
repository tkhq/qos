//! Bounded Borsh transport types for OCI image artifacts.

use borsh::{BorshDeserialize, BorshSerialize};

use super::services::boot::OciDigest;

const MEBIBYTE: usize = 1024 * 1024;
/// Maximum number of distinct OCI images in one boot request.
pub const MAX_OCI_ARTIFACTS: usize = 16;
/// Maximum encoded Manifest V3 envelope size.
pub const MAX_OCI_MANIFEST_ENVELOPE_BYTES: usize = MEBIBYTE;
/// Maximum size of one uncompressed OCI image-layout archive.
pub const MAX_OCI_LAYOUT_ARCHIVE_BYTES: usize = 120 * MEBIBYTE;
/// Maximum total image archive bytes in one boot request.
pub const MAX_OCI_TOTAL_ARCHIVE_BYTES: usize = 120 * MEBIBYTE;

fn read_len<R: borsh::io::Read>(
	reader: &mut R,
	max: usize,
	label: &str,
) -> borsh::io::Result<usize> {
	let len = u32::deserialize_reader(reader)? as usize;
	if len > max {
		return Err(borsh::io::Error::new(
			borsh::io::ErrorKind::InvalidData,
			format!("{label} exceeds limit"),
		));
	}
	Ok(len)
}

fn read_bytes<R: borsh::io::Read>(
	reader: &mut R,
	max: usize,
	label: &str,
) -> borsh::io::Result<Vec<u8>> {
	let len = read_len(reader, max, label)?;
	let mut bytes = vec![0; len];
	reader.read_exact(&mut bytes)?;
	Ok(bytes)
}

macro_rules! bounded_bytes_type {
	(
		$(#[$meta:meta])*
		$name:ident, $max:expr, $error:literal, $label:literal
	) => {
		$(#[$meta])*
		#[derive(Debug, PartialEq, Eq, BorshSerialize)]
		pub struct $name(Vec<u8>);

		impl $name {
			/// Construct a bounded byte string.
			///
			/// # Errors
			///
			/// Returns an error when `bytes` exceeds this type's limit.
			pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
				(bytes.len() <= $max).then_some(Self(bytes)).ok_or($error)
			}

			/// Borrow the encoded bytes.
			#[must_use]
			pub fn as_slice(&self) -> &[u8] {
				&self.0
			}
		}

		impl BorshDeserialize for $name {
			fn deserialize_reader<R: borsh::io::Read>(
				reader: &mut R,
			) -> borsh::io::Result<Self> {
				Ok(Self(read_bytes(reader, $max, $label)?))
			}
		}
	};
}

bounded_bytes_type!(
	/// Existing QOS encoding of a signed Manifest V3 envelope.
	ManifestEnvelopeBytes,
	MAX_OCI_MANIFEST_ENVELOPE_BYTES,
	"manifest envelope exceeds OCI boot limit",
	"manifest envelope"
);

bounded_bytes_type!(
	/// Uncompressed POSIX tar containing an OCI image layout.
	OciLayoutArchive,
	MAX_OCI_LAYOUT_ARCHIVE_BYTES,
	"OCI layout archive exceeds per-artifact limit",
	"OCI layout archive"
);

/// One digest-addressed OCI image-layout archive.
#[derive(Debug, PartialEq, Eq, BorshSerialize)]
pub struct OciArtifactV3 {
	/// Claimed root image-manifest digest.
	pub digest: OciDigest,
	/// Raw image-layout tar bytes.
	pub oci_layout_archive: OciLayoutArchive,
}

impl OciArtifactV3 {
	fn read_with_limit<R: borsh::io::Read>(
		reader: &mut R,
		remaining: usize,
	) -> borsh::io::Result<Self> {
		let digest = OciDigest::deserialize_reader(reader)?;
		let max = remaining.min(MAX_OCI_LAYOUT_ARCHIVE_BYTES);
		let archive = read_bytes(reader, max, "OCI layout archive")?;
		Ok(Self { digest, oci_layout_archive: OciLayoutArchive(archive) })
	}
}

impl BorshDeserialize for OciArtifactV3 {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		Self::read_with_limit(reader, MAX_OCI_LAYOUT_ARCHIVE_BYTES)
	}
}

/// Borsh payload used by standard and key-forward OCI boot requests.
#[derive(Debug, PartialEq, Eq, BorshSerialize)]
pub struct OciBootPayloadV3 {
	/// Encoded signed Manifest V3 envelope.
	pub manifest_envelope: ManifestEnvelopeBytes,
	/// Exactly one artifact per distinct approved digest.
	pub artifacts: Vec<OciArtifactV3>,
}

impl BorshDeserialize for OciBootPayloadV3 {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let manifest_envelope =
			ManifestEnvelopeBytes::deserialize_reader(reader)?;
		let count = read_len(reader, MAX_OCI_ARTIFACTS, "OCI artifact count")?;
		let mut artifacts = Vec::with_capacity(count);
		let mut remaining = MAX_OCI_TOTAL_ARCHIVE_BYTES;
		for _ in 0..count {
			let artifact = OciArtifactV3::read_with_limit(reader, remaining)?;
			remaining -= artifact.oci_layout_archive.0.len();
			artifacts.push(artifact);
		}
		Ok(Self { manifest_envelope, artifacts })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decoder_rejects_an_oversized_archive_before_reading_it() {
		let mut encoded =
			borsh::to_vec(&ManifestEnvelopeBytes::new(vec![]).unwrap())
				.unwrap();
		encoded.extend_from_slice(&1_u32.to_le_bytes());
		OciDigest::try_from(format!("sha256:{}", "0".repeat(64)))
			.unwrap()
			.serialize(&mut encoded)
			.unwrap();
		let oversized =
			u32::try_from(MAX_OCI_LAYOUT_ARCHIVE_BYTES).unwrap() + 1;
		encoded.extend_from_slice(&oversized.to_le_bytes());
		assert!(OciBootPayloadV3::try_from_slice(&encoded).is_err());
	}
}
