//! Canonical JSON serialization for QOS types.
//!
//! # Key features
//!
//! - Alphabetically sorted object keys (at runtime, via [`sort_keys`])
//! - Numbers serialized as base-10 strings (via [`string_number`] module)
//! - Optional fields omitted when None
//! - Compact output (no whitespace)
//!
//! # Instrumenting types for canonical JSON
//!
//! ```rust,ignore
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! #[serde(rename_all = "camelCase")]  // Use camelCase for JSON keys
//! struct MyType {
//!     // Binary data as lowercase hex
//!     #[serde(with = "qos_hex::serde")]
//!     data: Vec<u8>,
//!
//!     // Numbers as base-10 strings for cross-language consistency
//!     #[serde(with = "qos_json::string_number")]
//!     threshold: u32,
//!
//!     // Optional fields omitted when None
//!     #[serde(default, skip_serializing_if = "Option::is_none")]
//!     optional_field: Option<String>,
//! }
//! ```
//!
//! Then serialize using [`to_vec`] or [`to_string`] which sort keys alphabetically.

use serde::Serialize;
use serde_json::Value;

/// Maximum recursion depth to prevent stack overflow attacks.
pub const MAX_DEPTH: usize = 8;

/// Error type for canonical JSON operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	/// Serialization error from serde_json.
	Serialization(String),
	/// Maximum recursion depth exceeded.
	MaxDepthExceeded,
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Serialization(msg) => {
				write!(f, "serialization error: {msg}")
			}
			Error::MaxDepthExceeded => write!(f, "max depth exceeded"),
		}
	}
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
	fn from(e: serde_json::Error) -> Self {
		Error::Serialization(e.to_string())
	}
}

/// Serialize to canonical JSON bytes with alphabetically sorted keys.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
	let v = serde_json::to_value(value)?;
	let sorted = sort_keys(&v, 0)?;
	Ok(serde_json::to_vec(&sorted)?)
}

/// Serialize to canonical JSON string with alphabetically sorted keys.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, Error> {
	let v = serde_json::to_value(value)?;
	let sorted = sort_keys(&v, 0)?;
	Ok(serde_json::to_string(&sorted)?)
}

/// Sort object keys alphabetically, recursively.
fn sort_keys(value: &Value, depth: usize) -> Result<Value, Error> {
	if depth > MAX_DEPTH {
		return Err(Error::MaxDepthExceeded);
	}

	match value {
		Value::Object(map) => {
			let mut sorted: serde_json::Map<String, Value> =
				serde_json::Map::new();
			let mut keys: Vec<&String> = map.keys().collect();
			keys.sort();
			for key in keys {
				let sorted_value = sort_keys(&map[key], depth + 1)?;
				sorted.insert(key.clone(), sorted_value);
			}
			Ok(Value::Object(sorted))
		}
		Value::Array(arr) => {
			// Note we don't actually sort the array, but we still want to recursively
			// sort any nested maps.
			let sorted: Result<Vec<Value>, _> =
				arr.iter().map(|v| sort_keys(v, depth + 1)).collect();
			Ok(Value::Array(sorted?))
		}
		_ => Ok(value.clone()),
	}
}

/// Serde serialization helpers for numbers as strings.
///
/// Use this module with `#[serde(with = "qos_json::string_number")]` to
/// serialize numeric types as base-10 strings.
pub mod string_number {
	use serde::{Deserialize, Deserializer, Serializer};
	use std::fmt::Display;
	use std::str::FromStr;

	/// Serialize a number as a base-10 string.
	pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
		T: Display,
	{
		serializer.serialize_str(&value.to_string())
	}

	/// Deserialize a base-10 string as a number.
	pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
	where
		D: Deserializer<'de>,
		T: FromStr,
		T::Err: std::fmt::Display,
	{
		let s = String::deserialize(deserializer)?;
		s.parse().map_err(serde::de::Error::custom)
	}
}

/// Serde serialization helpers for optional numbers as strings.
///
/// Use this module with `#[serde(with = "qos_json::string_number_opt")]` to
/// serialize optional numeric types as base-10 strings.
pub mod string_number_opt {
	use serde::{Deserialize, Deserializer, Serializer};
	use std::fmt::Display;
	use std::str::FromStr;

	/// Serialize an optional number as a base-10 string.
	pub fn serialize<S, T>(
		value: &Option<T>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
		T: Display,
	{
		match value {
			Some(v) => serializer.serialize_some(&v.to_string()),
			None => serializer.serialize_none(),
		}
	}

	/// Deserialize a base-10 string as an optional number.
	pub fn deserialize<'de, D, T>(
		deserializer: D,
	) -> Result<Option<T>, D::Error>
	where
		D: Deserializer<'de>,
		T: FromStr,
		T::Err: std::fmt::Display,
	{
		let opt: Option<String> = Option::deserialize(deserializer)?;
		match opt {
			Some(s) => {
				let v = s.parse().map_err(serde::de::Error::custom)?;
				Ok(Some(v))
			}
			None => Ok(None),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::{Deserialize, Serialize};

	#[test]
	fn sort_keys_simple() {
		#[derive(Serialize)]
		struct Example {
			zebra: u32,
			alpha: String,
			beta: bool,
		}

		let example =
			Example { zebra: 1, alpha: "test".to_string(), beta: true };
		let json = to_string(&example).unwrap();
		assert_eq!(json, r#"{"alpha":"test","beta":true,"zebra":1}"#);
	}

	#[test]
	fn sort_keys_nested() {
		#[derive(Serialize)]
		struct Inner {
			z: u32,
			a: u32,
		}

		#[derive(Serialize)]
		struct Outer {
			inner: Inner,
			name: String,
		}

		let example =
			Outer { inner: Inner { z: 2, a: 1 }, name: "test".into() };
		let json = to_string(&example).unwrap();
		assert_eq!(json, r#"{"inner":{"a":1,"z":2},"name":"test"}"#);
	}

	#[test]
	fn string_number_serialize_deserialize() {
		#[derive(Serialize, Deserialize, PartialEq, Debug)]
		struct Example {
			#[serde(with = "string_number")]
			count: u32,
		}

		let example = Example { count: 42 };
		let json = serde_json::to_string(&example).unwrap();
		assert_eq!(json, r#"{"count":"42"}"#);

		let decoded: Example = serde_json::from_str(&json).unwrap();
		assert_eq!(decoded, example);
	}

	#[test]
	fn string_number_opt_serialize_deserialize() {
		#[derive(Serialize, Deserialize, PartialEq, Debug)]
		struct Example {
			#[serde(
				default,
				skip_serializing_if = "Option::is_none",
				with = "string_number_opt"
			)]
			count: Option<u32>,
		}

		// Some value
		let example = Example { count: Some(42) };
		let json = serde_json::to_string(&example).unwrap();
		assert_eq!(json, r#"{"count":"42"}"#);

		let decoded: Example = serde_json::from_str(&json).unwrap();
		assert_eq!(decoded, example);

		// None value
		let example = Example { count: None };
		let json = serde_json::to_string(&example).unwrap();
		assert_eq!(json, r#"{}"#);
	}

	#[test]
	fn max_depth_exceeded() {
		// Create a deeply nested structure
		let mut value = serde_json::json!({"a": 1});
		for _ in 0..100 {
			value = serde_json::json!({"nested": value});
		}

		let result = sort_keys(&value, 0);
		assert!(matches!(result, Err(Error::MaxDepthExceeded)));
	}

	#[test]
	fn canonical_json_determinism() {
		// Ensure the same data always produces the same output
		#[derive(Serialize)]
		struct Example {
			c: u32,
			a: u32,
			b: u32,
		}

		let example = Example { c: 3, a: 1, b: 2 };
		let json1 = to_vec(&example).unwrap();
		let json2 = to_vec(&example).unwrap();
		assert_eq!(json1, json2);
		assert_eq!(json1, br#"{"a":1,"b":2,"c":3}"#);
	}

	#[test]
	fn array_of_objects_sorts_keys() {
		use std::collections::HashMap;

		let mut map1 = HashMap::new();
		map1.insert("zebra".to_string(), "z".to_string());
		map1.insert("alpha".to_string(), "a".to_string());

		let mut map2 = HashMap::new();
		map2.insert("gamma".to_string(), "g".to_string());
		map2.insert("beta".to_string(), "b".to_string());

		let items: Vec<HashMap<String, String>> = vec![map1, map2];
		let json = to_string(&items).unwrap();

		// Each object in the array should have sorted keys
		assert_eq!(
			json,
			r#"[{"alpha":"a","zebra":"z"},{"beta":"b","gamma":"g"}]"#
		);
	}

	// SPEC.md test vector: Simple Object
	#[test]
	fn spec_vector_simple_object() {
		#[derive(Serialize)]
		struct Example {
			threshold: &'static str,
			version: &'static str,
			name: &'static str,
		}

		let example = Example { threshold: "3", version: "1", name: "test" };
		let json = to_string(&example).unwrap();
		// Keys should be sorted alphabetically
		assert_eq!(json, r#"{"name":"test","threshold":"3","version":"1"}"#);
	}

	// SPEC.md test vector: Nested Object
	#[test]
	fn spec_vector_nested_object() {
		#[derive(Serialize)]
		struct Manifest {
			namespace: &'static str,
			version: &'static str,
		}

		#[derive(Serialize)]
		struct Example {
			manifest: Manifest,
			threshold: &'static str,
		}

		let example = Example {
			manifest: Manifest { namespace: "prod", version: "2" },
			threshold: "3",
		};
		let json = to_string(&example).unwrap();
		assert_eq!(
			json,
			r#"{"manifest":{"namespace":"prod","version":"2"},"threshold":"3"}"#
		);
	}

	// SPEC.md test vector: Binary Data (Hex Encoding)
	#[test]
	fn spec_vector_binary_data_hex() {
		#[derive(Serialize)]
		struct Example {
			#[serde(with = "qos_hex::serde")]
			data: Vec<u8>,
		}

		let example = Example { data: vec![0xde, 0xad, 0xbe, 0xef] };
		let json = to_string(&example).unwrap();
		assert_eq!(json, r#"{"data":"deadbeef"}"#);
	}

	// SPEC.md test vector: Externally Tagged Enum (Unit Variant)
	#[test]
	fn spec_vector_enum_unit_variant() {
		#[derive(Serialize)]
		#[serde(rename_all = "camelCase")]
		enum RestartPolicy {
			Never,
		}

		let policy = RestartPolicy::Never;
		let json = serde_json::to_string(&policy).unwrap();
		assert_eq!(json, r#""never""#);
	}

	// SPEC.md test vector: Externally Tagged Enum (Tuple Variant)
	#[test]
	fn spec_vector_enum_tuple_variant() {
		#[derive(Serialize)]
		#[serde(rename_all = "camelCase")]
		enum BridgeConfig {
			Server(String, String),
		}

		let config =
			BridgeConfig::Server("3000".to_string(), "0.0.0.0".to_string());
		let json = to_string(&config).unwrap();
		assert_eq!(json, r#"{"server":["3000","0.0.0.0"]}"#);
	}

	// SPEC.md test vector: Externally Tagged Enum (Struct Variant)
	#[test]
	fn spec_vector_enum_struct_variant() {
		#[derive(Serialize)]
		#[serde(rename_all = "camelCase")]
		enum Message {
			Request { data: String, id: String },
		}

		let msg =
			Message::Request { id: "42".to_string(), data: "abcd".to_string() };
		let json = to_string(&msg).unwrap();
		// Fields should be sorted alphabetically within the struct variant
		assert_eq!(json, r#"{"request":{"data":"abcd","id":"42"}}"#);
	}

	// SPEC.md test vector: Optional Field (None)
	#[test]
	fn spec_vector_optional_field_none() {
		#[derive(Serialize)]
		struct Config {
			name: String,
			#[serde(skip_serializing_if = "Option::is_none")]
			debug: Option<bool>,
		}

		let config = Config { name: "test".to_string(), debug: None };
		let json = to_string(&config).unwrap();
		// debug field should be omitted entirely
		assert_eq!(json, r#"{"name":"test"}"#);
	}

	// SPEC.md test vector: Optional Field (Some)
	#[test]
	fn spec_vector_optional_field_some() {
		#[derive(Serialize)]
		struct Config {
			name: String,
			#[serde(skip_serializing_if = "Option::is_none")]
			debug: Option<bool>,
		}

		let config = Config { name: "test".to_string(), debug: Some(true) };
		let json = to_string(&config).unwrap();
		// Fields sorted alphabetically: debug comes before name
		assert_eq!(json, r#"{"debug":true,"name":"test"}"#);
	}
}
