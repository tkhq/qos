#![doc = include_str!("../SPEC.md")]

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// A SHA-256 digest.
pub type Hash256 = [u8; 32];

/// Serialize a value as QOS canonical JSON bytes.
///
/// Typed values are first converted into `serde_json::Value` and then
/// canonicalized. This matches the inbound JSON hashing path, where bytes are
/// parsed and re-encoded before hashing.
///
/// # Errors
///
/// Returns an error if serde serialization or canonical JSON serialization
/// fails, including if the value contains a JSON number. QOS canonical JSON
/// requires numeric values to be encoded as decimal strings.
pub fn to_vec<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
	let value = serde_json::to_value(value)?;
	to_vec_value(&value)
}

/// Serialize a value as a QOS canonical JSON string.
///
/// # Errors
///
/// Returns an error if serde serialization or canonical JSON serialization
/// fails, including if the value contains a JSON number. QOS canonical JSON
/// requires numeric values to be encoded as decimal strings.
pub fn to_string<T: Serialize>(value: &T) -> serde_json::Result<String> {
	let value = serde_json::to_value(value)?;
	to_string_value(&value)
}

/// Parse JSON bytes and re-encode them as QOS canonical JSON bytes.
///
/// # Errors
///
/// Returns an error if parsing or canonicalization fails, including if the
/// parsed value contains a JSON number. QOS canonical JSON requires numeric
/// values to be encoded as decimal strings.
pub fn canonicalize_slice(bytes: &[u8]) -> serde_json::Result<Vec<u8>> {
	let value: serde_json::Value = serde_json::from_slice(bytes)?;
	to_vec_value(&value)
}

/// Parse a JSON string and re-encode it as a QOS canonical JSON string.
///
/// # Errors
///
/// Returns an error if parsing or canonicalization fails, including if the
/// parsed value contains a JSON number. QOS canonical JSON requires numeric
/// values to be encoded as decimal strings.
pub fn canonicalize_str(json: &str) -> serde_json::Result<String> {
	let value: serde_json::Value = serde_json::from_str(json)?;
	to_string_value(&value)
}

/// Deserialize JSON bytes as `T`.
///
/// # Errors
///
/// Returns an error if the bytes are not valid JSON for `T`.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
	serde_json::from_slice(bytes)
}

/// Hash a typed value after QOS canonical JSON serialization.
///
/// # Errors
///
/// Returns an error if serialization or canonicalization fails, including if
/// the value contains a JSON number. QOS canonical JSON requires numeric values
/// to be encoded as decimal strings.
pub fn hash<T: Serialize>(value: &T) -> serde_json::Result<Hash256> {
	let canonical = to_vec(value)?;
	Ok(sha_256(&canonical))
}

/// Hash inbound JSON after parsing and QOS re-canonicalization.
///
/// # Errors
///
/// Returns an error if parsing or canonicalization fails, including if the
/// parsed value contains a JSON number. QOS canonical JSON requires numeric
/// values to be encoded as decimal strings.
pub fn hash_json_slice(bytes: &[u8]) -> serde_json::Result<Hash256> {
	let canonical = canonicalize_slice(bytes)?;
	Ok(sha_256(&canonical))
}

/// Hash a typed value and return the lowercase hex digest.
///
/// # Errors
///
/// Returns an error if serialization or canonicalization fails, including if
/// the value contains a JSON number. QOS canonical JSON requires numeric values
/// to be encoded as decimal strings.
pub fn hash_hex<T: Serialize>(value: &T) -> serde_json::Result<String> {
	hash(value).map(|hash| qos_hex::encode(&hash))
}

fn sha_256(bytes: &[u8]) -> Hash256 {
	let mut hasher = Sha256::new();
	hasher.update(bytes);
	hasher.finalize().into()
}

fn to_vec_value(value: &serde_json::Value) -> serde_json::Result<Vec<u8>> {
	let mut bytes = Vec::new();
	to_writer_value(&mut bytes, value)?;
	Ok(bytes)
}

fn to_string_value(value: &serde_json::Value) -> serde_json::Result<String> {
	let bytes = to_vec_value(value)?;
	String::from_utf8(bytes).map_err(|err| {
		serde_json::Error::io(io::Error::new(io::ErrorKind::InvalidData, err))
	})
}

fn to_writer_value<W>(
	writer: &mut W,
	value: &serde_json::Value,
) -> serde_json::Result<()>
where
	W: ?Sized + Write,
{
	write_value(writer, value).map_err(serde_json::Error::io)
}

fn write_value<W>(writer: &mut W, value: &serde_json::Value) -> io::Result<()>
where
	W: ?Sized + Write,
{
	match value {
		// Preserve null values outside object fields. A top-level `null` is a
		// complete JSON value, and array nulls are positional data: `[null,"1"]`
		// must not canonicalize to `["1"]`. Dynamic array positions do not provide
		// the same domain separation as object field names. We do drop null object
		// fields in `write_object`, where field-name domain separation makes it safe.
		serde_json::Value::Null => writer.write_all(b"null"),
		serde_json::Value::Bool(true) => writer.write_all(b"true"),
		serde_json::Value::Bool(false) => writer.write_all(b"false"),
		serde_json::Value::Number(_) => Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"QOS canonical JSON forbids JSON numbers",
		)),
		serde_json::Value::String(value) => write_string(writer, value),
		serde_json::Value::Array(values) => write_array(writer, values),
		serde_json::Value::Object(map) => write_object(writer, map),
	}
}

fn write_array<W>(
	writer: &mut W,
	values: &[serde_json::Value],
) -> io::Result<()>
where
	W: ?Sized + Write,
{
	writer.write_all(b"[")?;
	for (index, value) in values.iter().enumerate() {
		if index > 0 {
			writer.write_all(b",")?;
		}
		write_value(writer, value)?;
	}
	writer.write_all(b"]")
}

fn write_object<W>(
	writer: &mut W,
	map: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<()>
where
	W: ?Sized + Write,
{
	// Drop null object fields before writing the object. This is safe because
	// the field name provides domain separation for each value:
	// `{"a":null,"b":"1"}` canonicalizes to `{"b":"1"}`. Arrays are not
	// filtered this way because array indexes are dynamic positions.
	let mut entries =
		map.iter().filter(|(_, value)| !value.is_null()).collect::<Vec<_>>();
	entries.sort_by(|(left, _), (right, _)| {
		left.encode_utf16().cmp(right.encode_utf16())
	});

	writer.write_all(b"{")?;
	for (index, (key, value)) in entries.into_iter().enumerate() {
		if index > 0 {
			writer.write_all(b",")?;
		}
		write_string(writer, key)?;
		writer.write_all(b":")?;
		write_value(writer, value)?;
	}
	writer.write_all(b"}")
}

fn write_string<W>(writer: &mut W, value: &str) -> io::Result<()>
where
	W: ?Sized + Write,
{
	serde_json::to_writer(writer, value).map_err(io::Error::other)
}

fn decimal_string_from_json_value<E>(
	value: serde_json::Value,
) -> Result<String, E>
where
	E: serde::de::Error,
{
	match value {
		serde_json::Value::String(s) => Ok(s),
		other => {
			Err(E::custom(format!("expected decimal string, got {other}")))
		}
	}
}

/// Serde serialization helpers for numbers as strings.
pub mod string_number {
	use serde::{Deserialize, Deserializer, Serialize, Serializer};
	use std::{collections::BTreeSet, fmt::Display, str::FromStr};

	/// Serialize a number as a base-10 string.
	///
	/// # Errors
	///
	/// Returns the serializer's error type if serialization fails.
	pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
		for<'a> &'a T: StringNumberSerialize,
	{
		value.serialize_string_number(serializer)
	}

	/// Deserialize a base-10 string as a number.
	///
	/// # Errors
	///
	/// Returns the deserializer's error type if the input is not a valid
	/// base-10 string for the target type.
	pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
	where
		D: Deserializer<'de>,
		T: StringNumberDeserialize<'de>,
	{
		T::deserialize_string_number(deserializer)
	}

	/// A type that can be serialized as one or more base-10 strings.
	pub trait StringNumberSerialize {
		/// Serialize the type as base-10 string JSON.
		///
		/// # Errors
		///
		/// Returns the serializer's error type if serialization fails.
		fn serialize_string_number<S>(
			self,
			serializer: S,
		) -> Result<S::Ok, S::Error>
		where
			S: Serializer;
	}

	macro_rules! impl_string_number_serialize {
		($($ty:ty),+ $(,)?) => {$(
			impl StringNumberSerialize for &$ty {
				fn serialize_string_number<S>(
					self,
					serializer: S,
				) -> Result<S::Ok, S::Error>
				where
					S: Serializer,
				{
					serializer.serialize_str(&self.to_string())
				}
			}
		)+};
	}

	impl_string_number_serialize!(
		u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
	);

	impl<T> StringNumberSerialize for &Option<T>
	where
		T: Display,
	{
		fn serialize_string_number<S>(
			self,
			serializer: S,
		) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			match self {
				Some(value) => serializer.serialize_some(&value.to_string()),
				None => serializer.serialize_none(),
			}
		}
	}

	impl<T> StringNumberSerialize for &BTreeSet<T>
	where
		T: Display,
	{
		fn serialize_string_number<S>(
			self,
			serializer: S,
		) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			let strings =
				self.iter().map(ToString::to_string).collect::<Vec<_>>();
			strings.serialize(serializer)
		}
	}

	/// A type that can be deserialized from one or more base-10 strings.
	pub trait StringNumberDeserialize<'de>: Sized {
		/// Deserialize the type from base-10 string JSON.
		///
		/// # Errors
		///
		/// Returns the deserializer's error type if the input is not a valid
		/// base-10 string for the target type.
		fn deserialize_string_number<D>(
			deserializer: D,
		) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>;
	}

	macro_rules! impl_string_number_deserialize {
		($($ty:ty),+ $(,)?) => {$(
			impl<'de> StringNumberDeserialize<'de> for $ty {
				fn deserialize_string_number<D>(
					deserializer: D,
				) -> Result<Self, D::Error>
				where
					D: Deserializer<'de>,
				{
					deserialize_string_number_value(deserializer)
				}
			}
		)+};
	}

	impl_string_number_deserialize!(
		u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
	);

	impl<'de, T> StringNumberDeserialize<'de> for Option<T>
	where
		T: FromStr,
		T::Err: Display,
	{
		fn deserialize_string_number<D>(
			deserializer: D,
		) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			let opt = Option::<serde_json::Value>::deserialize(deserializer)?;
			opt.map(parse_string_number_value).transpose()
		}
	}

	impl<'de, T> StringNumberDeserialize<'de> for BTreeSet<T>
	where
		T: FromStr + Ord,
		T::Err: Display,
	{
		fn deserialize_string_number<D>(
			deserializer: D,
		) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			let values = Vec::<serde_json::Value>::deserialize(deserializer)?;
			values.into_iter().map(parse_string_number_value).collect()
		}
	}

	fn deserialize_string_number_value<'de, D, T>(
		deserializer: D,
	) -> Result<T, D::Error>
	where
		D: Deserializer<'de>,
		T: FromStr,
		T::Err: Display,
	{
		let value = serde_json::Value::deserialize(deserializer)?;
		parse_string_number_value(value)
	}

	fn parse_string_number_value<E, T>(value: serde_json::Value) -> Result<T, E>
	where
		E: serde::de::Error,
		T: FromStr,
		T::Err: Display,
	{
		let s = super::decimal_string_from_json_value::<E>(value)?;
		s.parse().map_err(serde::de::Error::custom)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::{Deserialize, Serialize};
	use std::collections::BTreeSet;

	#[test]
	fn canonicalizes_key_order_before_hashing() {
		let a = br#"{"version":"1","name":"test","threshold":"3"}"#;
		let b = br#"{
			"threshold": "3",
			"name": "test",
			"version": "1"
		}"#;

		assert_eq!(
			canonicalize_slice(a).unwrap(),
			canonicalize_slice(b).unwrap()
		);
		assert_eq!(hash_json_slice(a).unwrap(), hash_json_slice(b).unwrap());
		assert_eq!(
			qos_hex::encode(&hash_json_slice(a).unwrap()),
			"898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e"
		);
	}

	#[test]
	fn typed_values_use_same_canonical_path() {
		#[derive(Serialize)]
		struct Example {
			version: &'static str,
			name: &'static str,
			threshold: &'static str,
		}

		let example = Example { version: "1", name: "test", threshold: "3" };
		assert_eq!(
			to_string(&example).unwrap(),
			r#"{"name":"test","threshold":"3","version":"1"}"#
		);
		assert_eq!(
			hash_hex(&example).unwrap(),
			"898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e"
		);
	}

	#[test]
	fn binary_hex_vector_matches_spec() {
		#[derive(Serialize)]
		struct Example {
			#[serde(with = "qos_hex::serde")]
			data: Vec<u8>,
		}

		let example = Example { data: vec![0xde, 0xad, 0xbe, 0xef] };
		assert_eq!(to_string(&example).unwrap(), r#"{"data":"deadbeef"}"#);
		assert_eq!(
			hash_hex(&example).unwrap(),
			"03fe564ceddcb54a7a742bd7a4db57318a068cecd22ae44435ce68d35e754e13"
		);
	}

	#[test]
	fn skip_serializing_if_none_is_not_needed_for_qos_json_output() {
		#[derive(Serialize)]
		struct WithSkip {
			name: &'static str,
			#[serde(default, skip_serializing_if = "Option::is_none")]
			maybe: Option<&'static str>,
		}

		#[derive(Serialize)]
		struct WithoutSkip {
			name: &'static str,
			#[serde(default)]
			maybe: Option<&'static str>,
		}

		let with_skip =
			to_string(&WithSkip { name: "test", maybe: None }).unwrap();
		let without_skip =
			to_string(&WithoutSkip { name: "test", maybe: None }).unwrap();

		assert_eq!(
			serde_json::to_string(&WithSkip { name: "test", maybe: None })
				.unwrap(),
			r#"{"name":"test"}"#
		);
		assert_eq!(
			serde_json::to_string(&WithoutSkip { name: "test", maybe: None })
				.unwrap(),
			r#"{"name":"test","maybe":null}"#
		);
		assert_eq!(with_skip, r#"{"name":"test"}"#);
		assert_eq!(with_skip, without_skip);
		assert_eq!(
			to_string(&WithSkip { name: "test", maybe: Some("value") })
				.unwrap(),
			to_string(&WithoutSkip { name: "test", maybe: Some("value") })
				.unwrap()
		);
	}

	#[test]
	fn object_null_members_are_omitted() {
		assert_eq!(
			canonicalize_str(r#"{"b":null,"a":"1","nested":{"z":null,"y":"2"},"items":[null,{"x":null,"y":true}]}"#).unwrap(),
			r#"{"a":"1","items":[null,{"y":true}],"nested":{"y":"2"}}"#
		);
		assert_eq!(
			hash_json_slice(br#"{"a":"1","b":null}"#).unwrap(),
			hash_json_slice(br#"{"a":"1"}"#).unwrap()
		);
	}

	#[test]
	fn object_null_members_are_omitted_but_array_nulls_remain() {
		assert_eq!(
			canonicalize_str(
				r#"{"empty":null,"items":[null,{"drop":null,"keep":"yes"},null]}"#
			)
			.unwrap(),
			r#"{"items":[null,{"keep":"yes"},null]}"#
		);
	}

	#[test]
	fn typed_optional_none_serializes_like_absent_field() {
		#[derive(Serialize)]
		struct Example {
			name: &'static str,
			#[serde(default)]
			comment: Option<&'static str>,
		}

		assert_eq!(
			to_string(&Example { name: "alice", comment: None }).unwrap(),
			canonicalize_str(r#"{"name":"alice"}"#).unwrap()
		);
		assert_eq!(
			to_string(&Example { name: "alice", comment: Some("ready") })
				.unwrap(),
			r#"{"comment":"ready","name":"alice"}"#
		);
	}

	#[test]
	fn errors_on_integer_json_numbers() {
		assert_qos_number_error(canonicalize_str(r#"{"n":1}"#));
		assert_qos_number_error(canonicalize_str(r#"{"n":-9007199254740991}"#));
	}

	#[test]
	fn errors_on_floating_point_json_numbers() {
		assert_qos_number_error(canonicalize_str(r#"{"n":1.0}"#));
		assert_qos_number_error(canonicalize_str(r#"{"n":1e0}"#));
		assert_qos_number_error(canonicalize_str(r#"{"n":-1.25}"#));
	}

	#[test]
	fn errors_on_typed_numeric_fields() {
		#[derive(Serialize)]
		struct Example {
			count: u32,
		}

		assert_qos_number_error(to_string(&Example { count: 42 }));
	}

	#[test]
	fn sorts_object_keys_by_utf16_code_units() {
		let canonical = canonicalize_str(
			r#"{
				"\u20ac": "Euro Sign",
				"\r": "Carriage Return",
				"\ufb33": "Hebrew Letter Dalet With Dagesh",
				"1": "One",
				"\ud83d\ude00": "Emoji: Grinning Face",
				"\u0080": "Control",
				"\u00f6": "Latin Small Letter O With Diaeresis"
			}"#,
		)
		.unwrap();

		let expected_values = [
			"Carriage Return",
			"One",
			"Control",
			"Latin Small Letter O With Diaeresis",
			"Euro Sign",
			"Emoji: Grinning Face",
			"Hebrew Letter Dalet With Dagesh",
		];
		let mut last_position = 0;
		for value in expected_values {
			let position = canonical[last_position..].find(value).unwrap();
			last_position += position + value.len();
		}
		assert_eq!(
			canonical,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
		);
	}

	#[test]
	fn recursively_sorts_objects_without_reordering_arrays() {
		assert_eq!(
			canonicalize_str(
				r#"{"z":{"b":"2","a":"1"},"a":[{"d":"4","c":"3"},"second",{"b":"2","a":"1"}]}"#
			)
			.unwrap(),
			r#"{"a":[{"c":"3","d":"4"},"second",{"a":"1","b":"2"}],"z":{"a":"1","b":"2"}}"#
		);
	}

	#[test]
	fn escaped_object_keys_sort_by_raw_key_and_remain_escaped() {
		assert_eq!(
			canonicalize_str(
				"{\"b\":\"plain\",\"\\n\":\"line feed\",\"\\r\":\"carriage return\",\"\\u0001\":\"control\"}"
			)
			.unwrap(),
			"{\"\\u0001\":\"control\",\"\\n\":\"line feed\",\"\\r\":\"carriage return\",\"b\":\"plain\"}"
		);
	}

	#[test]
	fn escapes_string_values_canonically() {
		assert_eq!(
			canonicalize_str(
				"{\"quote\":\"\\\"\",\"slash\":\"/\",\"control\":\"\\u0001\",\"line\":\"a\\nb\",\"unicode\":\"€\"}"
			)
			.unwrap(),
			"{\"control\":\"\\u0001\",\"line\":\"a\\nb\",\"quote\":\"\\\"\",\"slash\":\"/\",\"unicode\":\"€\"}"
		);
	}

	#[test]
	fn canonicalizes_raw_json_whitespace_and_order() {
		assert_eq!(
			canonicalize_str(
				"{\n  \"z\": [ true, false, null ],\n  \"a\": { \"b\": \"2\", \"a\": \"1\" }\n}"
			)
			.unwrap(),
			r#"{"a":{"a":"1","b":"2"},"z":[true,false,null]}"#
		);
	}

	#[test]
	fn supports_external_enums_and_decimal_string_numbers() {
		#[derive(Serialize)]
		#[serde(rename_all = "camelCase")]
		enum Example {
			Request {
				#[serde(with = "string_number")]
				count: u32,
			},
		}

		assert_eq!(
			to_string(&Example::Request { count: 42 }).unwrap(),
			r#"{"request":{"count":"42"}}"#
		);
	}

	#[test]
	fn string_number_supports_signed_and_collection_values() {
		#[derive(Serialize)]
		struct Example {
			#[serde(with = "string_number")]
			offset: i32,
			#[serde(with = "string_number")]
			indexes: BTreeSet<u8>,
		}

		assert_eq!(
			to_string(&Example {
				offset: -7,
				indexes: BTreeSet::from([2, 10]),
			})
			.unwrap(),
			r#"{"indexes":["2","10"],"offset":"-7"}"#
		);
	}

	#[test]
	fn typed_and_raw_inputs_produce_same_hash() {
		#[derive(Serialize)]
		struct Example {
			#[serde(with = "string_number")]
			threshold: u32,
			name: &'static str,
		}

		let typed = Example { threshold: 3, name: "test" };
		let raw = br#"{"threshold":"3","name":"test","unused":null}"#;
		assert_eq!(
			to_string(&typed).unwrap(),
			canonicalize_slice(raw)
				.map(|bytes| String::from_utf8(bytes).unwrap())
				.unwrap()
		);
		assert_eq!(hash(&typed).unwrap(), hash_json_slice(raw).unwrap());
	}

	#[test]
	fn empty_arrays_and_objects_are_preserved() {
		assert_eq!(
			canonicalize_str(
				r#"{"empty_object":{},"empty_array":[],"null_member":null}"#
			)
			.unwrap(),
			r#"{"empty_array":[],"empty_object":{}}"#
		);
	}

	#[test]
	fn string_number_round_trips() {
		#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
		struct Example {
			#[serde(with = "string_number")]
			count: u32,
			#[serde(default, with = "string_number")]
			limit: Option<u64>,
		}

		let example = Example { count: 42, limit: None };
		let json = to_string(&example).unwrap();
		assert_eq!(json, r#"{"count":"42"}"#);
		assert_eq!(from_slice::<Example>(json.as_bytes()).unwrap(), example);
	}

	#[test]
	fn string_number_helpers_reject_json_numbers() {
		#[derive(Debug, PartialEq, Eq, Deserialize)]
		struct Example {
			#[serde(with = "string_number")]
			count: u32,
			#[serde(default, with = "string_number")]
			limit: Option<u64>,
			#[serde(with = "string_number")]
			indexes: BTreeSet<u8>,
		}

		let parsed = from_slice::<Example>(
			br#"{"count":"42","limit":"7","indexes":["1","2"]}"#,
		)
		.unwrap();
		assert_eq!(parsed.count, 42);
		assert_eq!(parsed.limit, Some(7));
		assert_eq!(parsed.indexes, BTreeSet::from([1, 2]));

		assert!(from_slice::<Example>(
			br#"{"count":42,"limit":"7","indexes":["1"]}"#
		)
		.is_err());
		assert!(from_slice::<Example>(
			br#"{"count":"42","limit":7,"indexes":["1"]}"#
		)
		.is_err());
		assert!(from_slice::<Example>(
			br#"{"count":"42","limit":"7","indexes":[1]}"#
		)
		.is_err());
	}

	fn assert_qos_number_error<T>(result: serde_json::Result<T>) {
		let Err(err) = result else {
			panic!("expected QOS number error");
		};
		assert_eq!(err.to_string(), "QOS canonical JSON forbids JSON numbers");
	}
}
