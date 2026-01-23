#![doc = include_str!("../README.md")]

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

	/// Simulates an "old" proto type before a new optional field was added.
	#[derive(Clone, PartialEq, prost::Message)]
	struct OldType {
		#[prost(string, tag = "1")]
		name: String,
		#[prost(uint64, tag = "2")]
		nonce: u64,
	}

	/// Simulates a "new" proto type with an additional optional field.
	/// When `new_field` is None, this should serialize identically to OldType.
	#[derive(Clone, PartialEq, prost::Message)]
	struct NewType {
		#[prost(string, tag = "1")]
		name: String,
		#[prost(uint64, tag = "2")]
		nonce: u64,
		#[prost(string, optional, tag = "3")]
		new_field: Option<String>,
	}

	#[test]
	fn old_and_new_types_have_same_proto_hash_when_new_field_is_none() {
		let old = OldType { name: "test".to_string(), nonce: 42 };

		let new_with_none =
			NewType { name: "test".to_string(), nonce: 42, new_field: None };

		// Both should serialize to identical bytes
		assert_eq!(old.encode_to_vec(), new_with_none.encode_to_vec());

		// Therefore they should have the same hash
		assert_eq!(old.proto_hash(), new_with_none.proto_hash());

		// But if the new field is set, the hash should differ
		let new_with_value = NewType {
			name: "test".to_string(),
			nonce: 42,
			new_field: Some("extra".to_string()),
		};
		assert_ne!(old.proto_hash(), new_with_value.proto_hash());
	}

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

	/// Simulates a "new" proto type with a NON-optional field (no `optional` keyword).
	/// In proto3, non-optional fields with default values are NOT serialized.
	#[derive(Clone, PartialEq, prost::Message)]
	struct NewTypeNonOptional {
		#[prost(string, tag = "1")]
		name: String,
		#[prost(uint64, tag = "2")]
		nonce: u64,
		#[prost(string, tag = "3")] // NOT optional - empty string is default
		new_field: String,
	}

	#[test]
	fn non_optional_field_with_default_value_does_not_change_hash() {
		let old = OldType { name: "test".to_string(), nonce: 42 };

		// Non-optional field set to default (empty string)
		let new_with_default = NewTypeNonOptional {
			name: "test".to_string(),
			nonce: 42,
			new_field: String::new(), // empty string = default
		};

		// Proto3 does NOT serialize fields with default values,
		// so the encoding is identical
		assert_eq!(
			old.encode_to_vec(),
			new_with_default.encode_to_vec(),
			"Empty non-optional field should not be serialized"
		);
		assert_eq!(old.proto_hash(), new_with_default.proto_hash());

		// But if the non-optional field has a non-default value, hash differs
		let new_with_value = NewTypeNonOptional {
			name: "test".to_string(),
			nonce: 42,
			new_field: "extra".to_string(),
		};
		assert_ne!(old.proto_hash(), new_with_value.proto_hash());
	}

	#[test]
	fn optional_vs_non_optional_difference() {
		// Key difference: optional fields CAN distinguish between
		// "not set" (None) and "set to default" (Some(""))

		let with_optional_none =
			NewType { name: "test".to_string(), nonce: 42, new_field: None };

		let with_optional_empty = NewType {
			name: "test".to_string(),
			nonce: 42,
			new_field: Some(String::new()), // explicitly set to empty
		};

		let with_non_optional_empty = NewTypeNonOptional {
			name: "test".to_string(),
			nonce: 42,
			new_field: String::new(),
		};

		// Optional None and non-optional default serialize the same (field omitted)
		assert_eq!(
			with_optional_none.encode_to_vec(),
			with_non_optional_empty.encode_to_vec()
		);

		// But optional Some("") is DIFFERENT - it serializes the empty string
		assert_ne!(
			with_optional_none.encode_to_vec(),
			with_optional_empty.encode_to_vec(),
		);
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
