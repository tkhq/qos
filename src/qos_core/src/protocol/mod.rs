//! Quorum protocol

use std::{sync::Arc, time::Duration};

use borsh::BorshSerialize;
use qos_crypto::sha_256;
use serde::Serialize;

mod error;
pub mod msg;
pub mod services;
mod state;

pub use error::ProtocolError;
pub use state::ProtocolPhase;
pub(crate) use state::ProtocolState;

pub(crate) mod processor;
use tokio::sync::RwLock;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

/// Initial client timeout for the processor until the Manifest says otherwise, see reaper.rs
pub const INITIAL_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// 256bit hash
pub type Hash256 = [u8; 32];

/// Canonical hash of legacy `QuorumOS` types using Borsh serialization.
///
/// Used for v0/v1 manifest schemas and other Borsh-encoded protocol types.
pub trait QosHash: BorshSerialize {
	/// Get the canonical hash via Borsh bytes.
	fn qos_hash(&self) -> Hash256 {
		sha_256(&borsh::to_vec(self).expect("Implements borsh serialize"))
	}
}

// Blanket implement QosHash for any type that implements BorshSerialize.
impl<T: BorshSerialize> QosHash for T {}

/// Canonical hash of `QuorumOS` types using QOS canonical JSON serialization.
///
/// Used for v2 manifest schemas and other types that opt into JSON-based
/// hashing. See `qos_json::SPEC.md` for the canonical JSON specification.
pub trait QosHashJson: Serialize {
	/// Get the canonical hash via QOS canonical JSON bytes.
	fn qos_hash_json(&self) -> Hash256
	where
		Self: Sized,
	{
		sha_256(
			&qos_json::to_vec(self).expect(
				"Implements serde serialize in a QOS JSON compatible way",
			),
		)
	}
}

// Blanket implement QosHashJson for any type that implements Serialize.
impl<T: Serialize> QosHashJson for T {}

/// Helper type to keep `ProtocolState` shared using `Arc<Mutex<ProtocolState>>`
type SharedProtocolState = Arc<RwLock<ProtocolState>>;

impl ProtocolState {
	/// Wrap this `ProtocolState` into a `Mutex` in an `Arc`.
	pub fn shared(self) -> SharedProtocolState {
		Arc::new(RwLock::new(self))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn qos_hash_borsh_deterministic_and_pinned() {
		#[derive(borsh::BorshSerialize)]
		struct Data {
			z: u32,
			a: u32,
		}

		let data = Data { z: 2, a: 1 };

		let hash1 = data.qos_hash();
		let hash2 = data.qos_hash();
		assert_eq!(hash1, hash2);

		// Borsh encoding is field-order, fixed-width little-endian. The bytes
		// are `02 00 00 00 01 00 00 00`; SHA-256 over those bytes is pinned
		// here so any change to the trait's encoding is caught.
		let expected_hex =
			"7b2ed67587fcbc411fcb4b71b1cef1ef6cd9edf948148414cf5f0ab21362b9aa";
		assert_eq!(qos_hex::encode(&hash1), expected_hex);
	}

	#[test]
	fn qos_hash_json_deterministic_and_pinned() {
		#[derive(serde::Serialize)]
		struct Example {
			name: &'static str,
			#[serde(with = "qos_json::string_number")]
			threshold: u32,
			version: &'static str,
		}

		let example = Example { name: "test", threshold: 3, version: "1" };

		let canonical_json = qos_json::to_string(&example).expect("serializes");
		assert_eq!(
			canonical_json,
			r#"{"name":"test","threshold":"3","version":"1"}"#
		);

		let hash1 = example.qos_hash_json();
		let hash2 = example.qos_hash_json();
		assert_eq!(hash1, hash2);

		let expected_hex =
			"898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e";
		assert_eq!(qos_hex::encode(&hash1), expected_hex);
	}

	#[test]
	fn qos_hash_json_sorts_keys_alphabetically() {
		#[derive(serde::Serialize)]
		struct Data {
			#[serde(with = "qos_json::string_number")]
			z: u32,
			#[serde(with = "qos_json::string_number")]
			a: u32,
		}

		let data = Data { z: 2, a: 1 };
		let canonical = qos_json::to_string(&data).unwrap();
		assert_eq!(canonical, r#"{"a":"1","z":"2"}"#);
	}
}
