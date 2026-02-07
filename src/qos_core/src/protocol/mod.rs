//! Quorum protocol

use std::{sync::Arc, time::Duration};

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

/// Canonical hash of `QuorumOS` types using JSON serialization.
///
/// This trait provides deterministic hashing via canonical JSON format.
/// See `qos_json::SPEC.md` for the canonical JSON specification.
pub trait QosHash: Serialize {
	/// Get the canonical hash using JSON serialization.
	fn qos_hash(&self) -> Hash256
	where
		Self: Sized,
	{
		sha_256(&qos_json::to_vec(self).expect("Implements serde serialize"))
	}
}

// Blanket implement QosHash for any type that implements Serialize.
impl<T: Serialize> QosHash for T {}

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
	fn qos_hash_produces_expected_sha256() {
		#[derive(serde::Serialize)]
		struct Example {
			name: &'static str,
			threshold: &'static str,
			version: &'static str,
		}

		let example = Example { name: "test", threshold: "3", version: "1" };

		// Get the canonical JSON
		let canonical_json = qos_json::to_string(&example).expect("serializes");
		assert_eq!(
			canonical_json,
			r#"{"name":"test","threshold":"3","version":"1"}"#
		);

		let hash = example.qos_hash();
		let expected_hex =
			"898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e";
		let actual_hex = qos_hex::encode(&hash);
		assert_eq!(actual_hex, expected_hex);
	}

	#[test]
	fn qos_hash_deterministic() {
		#[derive(serde::Serialize)]
		struct Data {
			z: u32,
			a: u32,
		}

		let data = Data { z: 2, a: 1 };

		let hash1 = data.qos_hash();
		let hash2 = data.qos_hash();
		assert_eq!(hash1, hash2);

		// Sorts keys alphabetically
		let canonical = qos_json::to_string(&data).unwrap();
		assert_eq!(canonical, r#"{"a":1,"z":2}"#);
	}
}
