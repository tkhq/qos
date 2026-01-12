//! Protocol buffer types for QOS.
//!
//! This crate provides the canonical protobuf-generated types for QOS,
//! enabling cross-language interoperability.
//!
//! ## Deterministic Encoding
//!
//! Types follow strict encoding rules for deterministic serialization:
//! - Fields serialized in ascending field number order
//! - No `map<>` fields (enforced by CI)
//! - `optional` for nullable fields
//! - Empty repeated fields not serialized
//!
//! See `docs/proto-encoding.md` for the complete specification.
//!
//! ## Hashing
//!
//! Use [`ProtoHash`] to compute deterministic hashes of proto types:
//!
//! ```ignore
//! use qos_proto::{Manifest, ProtoHash};
//! let hash = manifest.proto_hash();
//! ```

mod gen;

pub use gen::qos::v1::*;
use prost::Message;
use qos_crypto::sha_256;

/// 256-bit hash.
pub type Hash256 = [u8; 32];

/// Compute a canonical hash of protobuf-encoded types.
///
/// This trait provides deterministic hashing by encoding the type
/// to protobuf bytes and then computing SHA-256.
pub trait ProtoHash: Message + Sized {
	/// Get the canonical hash (proto encode → SHA-256).
	fn proto_hash(&self) -> Hash256 {
		sha_256(&self.encode_to_vec())
	}
}

// Blanket implement ProtoHash for any type that implements prost::Message.
impl<T: Message + Sized> ProtoHash for T {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn proto_hash_is_deterministic() {
		let manifest = Manifest {
			namespace: Some(Namespace {
				name: "test".to_string(),
				nonce: 42,
				quorum_key: vec![1, 2, 3],
			}),
			..Default::default()
		};

		let hash1 = manifest.proto_hash();
		let hash2 = manifest.proto_hash();

		assert_eq!(hash1, hash2);
	}

	#[test]
	fn different_manifests_have_different_hashes() {
		let manifest1 = Manifest {
			namespace: Some(Namespace {
				name: "test1".to_string(),
				nonce: 1,
				quorum_key: vec![],
			}),
			..Default::default()
		};

		let manifest2 = Manifest {
			namespace: Some(Namespace {
				name: "test2".to_string(),
				nonce: 2,
				quorum_key: vec![],
			}),
			..Default::default()
		};

		assert_ne!(manifest1.proto_hash(), manifest2.proto_hash());
	}
}
