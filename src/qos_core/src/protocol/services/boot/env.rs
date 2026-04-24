//! Pivot environment variable manifest types.

use std::{borrow::Borrow, collections::BTreeMap, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::ser::SerializeStruct;

use crate::protocol::ProtocolError;

/// Maximum number of env vars in a pivot manifest.
pub const MAX_PIVOT_ENV_VARS: usize = 512;
/// Maximum pivot env var name length in bytes.
pub const MAX_PIVOT_ENV_NAME_LEN: usize = 1024;
/// Maximum pivot env var value length in bytes.
pub const MAX_PIVOT_ENV_VALUE_LEN: usize = 64 * 1024;
/// Maximum total pivot env payload size in bytes.
pub const MAX_PIVOT_ENV_TOTAL_LEN: usize = 512 * 1024;

/// Environment variable name to inject into the pivot process.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct PivotEnvVarName(String);

impl PivotEnvVarName {
	/// Parse and validate an environment variable name.
	pub fn new(name: String) -> Result<Self, ProtocolError> {
		if name.len() > MAX_PIVOT_ENV_NAME_LEN {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"env var `{name}` name too long: {} > {}",
				name.len(),
				MAX_PIVOT_ENV_NAME_LEN
			)));
		}

		let mut chars = name.chars();
		let Some(first) = chars.next() else {
			return Err(ProtocolError::InvalidPivotEnv(
				"env var name cannot be empty".to_string(),
			));
		};

		if !(first.is_ascii_alphabetic() || first == '_') {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"env var name `{name}` must start with [A-Za-z_]"
			)));
		}

		if chars.any(|c| !(c.is_ascii_alphanumeric() || c == '_')) {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"env var name `{name}` must match [A-Za-z_][A-Za-z0-9_]*"
			)));
		}

		Ok(Self(name))
	}

	/// Return the validated name as a string slice.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl fmt::Debug for PivotEnvVarName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl fmt::Display for PivotEnvVarName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl Borrow<str> for PivotEnvVarName {
	fn borrow(&self) -> &str {
		self.as_str()
	}
}

impl TryFrom<String> for PivotEnvVarName {
	type Error = ProtocolError;

	fn try_from(name: String) -> Result<Self, Self::Error> {
		Self::new(name)
	}
}

impl BorshSerialize for PivotEnvVarName {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		self.0.serialize(writer)
	}
}

impl BorshDeserialize for PivotEnvVarName {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let name = String::deserialize_reader(reader)?;
		Self::new(name).map_err(|e| {
			borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e)
		})
	}
}

impl serde::Serialize for PivotEnvVarName {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(self.as_str())
	}
}

impl<'de> serde::Deserialize<'de> for PivotEnvVarName {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let name = <String as serde::Deserialize>::deserialize(deserializer)?;
		Self::new(name).map_err(serde::de::Error::custom)
	}
}

/// Environment variable value to inject into the pivot process.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum PivotEnvValue {
	/// A plain, non-secret environment variable value.
	Plain {
		/// Value to set for the environment variable.
		value: String,
	},
}

impl PivotEnvValue {
	/// Parse and validate a plain environment variable value.
	pub fn plain(value: String) -> Result<Self, ProtocolError> {
		if value.contains('\0') {
			return Err(ProtocolError::InvalidPivotEnv(
				"env var value cannot contain NUL".to_string(),
			));
		}
		if value.len() > MAX_PIVOT_ENV_VALUE_LEN {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"env var value too long: {} > {}",
				value.len(),
				MAX_PIVOT_ENV_VALUE_LEN
			)));
		}

		Ok(Self::Plain { value })
	}

	/// Return the string value to inject into the pivot process.
	#[must_use]
	pub fn as_plain_value(&self) -> Option<&str> {
		match self {
			Self::Plain { value } => Some(value),
		}
	}
}

impl BorshSerialize for PivotEnvValue {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		match self {
			Self::Plain { value } => {
				0u8.serialize(writer)?;
				value.serialize(writer)
			}
		}
	}
}

impl BorshDeserialize for PivotEnvValue {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let variant = u8::deserialize_reader(reader)?;
		match variant {
			0 => {
				let value = String::deserialize_reader(reader)?;
				Self::plain(value).map_err(|e| {
					borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e)
				})
			}
			_ => Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				format!("invalid pivot env value variant: {variant}"),
			)),
		}
	}
}

impl serde::Serialize for PivotEnvValue {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		match self {
			Self::Plain { value } => {
				let mut state =
					serializer.serialize_struct("PivotEnvValue", 2)?;
				state.serialize_field("kind", "plain")?;
				state.serialize_field("value", value)?;
				state.end()
			}
		}
	}
}

impl<'de> serde::Deserialize<'de> for PivotEnvValue {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(serde::Deserialize)]
		#[serde(tag = "kind", rename_all = "camelCase")]
		enum PivotEnvValueDef {
			#[serde(rename = "plain")]
			Plain { value: String },
		}

		match PivotEnvValueDef::deserialize(deserializer)? {
			PivotEnvValueDef::Plain { value } => {
				Self::plain(value).map_err(serde::de::Error::custom)
			}
		}
	}
}

/// Environment variables to inject into the pivot process.
#[derive(PartialEq, Eq, Clone, Default)]
#[repr(transparent)]
pub struct PivotEnv(BTreeMap<PivotEnvVarName, PivotEnvValue>);

impl PivotEnv {
	/// Create an empty pivot environment.
	#[must_use]
	pub fn new() -> Self {
		Self(BTreeMap::new())
	}

	/// Return the number of environment variables.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Return true if there are no environment variables.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Iterate over environment variable names and values.
	pub fn iter(
		&self,
	) -> impl Iterator<Item = (&PivotEnvVarName, &PivotEnvValue)> {
		self.0.iter()
	}

	/// Insert an environment variable.
	pub fn insert(
		&mut self,
		name: PivotEnvVarName,
		value: PivotEnvValue,
	) -> Result<Option<PivotEnvValue>, ProtocolError> {
		let previous = self.0.insert(name.clone(), value);
		if let Err(err) = self.check_aggregate_limits() {
			if let Some(previous) = previous {
				self.0.insert(name, previous);
			} else {
				self.0.remove(&name);
			}
			return Err(err);
		}

		Ok(previous)
	}

	/// Get an environment variable by name.
	#[must_use]
	pub fn get(&self, name: &str) -> Option<&PivotEnvValue> {
		self.0.get(name)
	}
}

impl TryFrom<BTreeMap<PivotEnvVarName, PivotEnvValue>> for PivotEnv {
	type Error = ProtocolError;

	fn try_from(
		value: BTreeMap<PivotEnvVarName, PivotEnvValue>,
	) -> Result<Self, Self::Error> {
		let env = Self(value);
		env.check_aggregate_limits()?;
		Ok(env)
	}
}

impl BorshSerialize for PivotEnv {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		self.0.serialize(writer)
	}
}

impl BorshDeserialize for PivotEnv {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let env =
			BTreeMap::<PivotEnvVarName, PivotEnvValue>::deserialize_reader(
				reader,
			)?;
		Self::try_from(env).map_err(|e| {
			borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e)
		})
	}
}

impl serde::Serialize for PivotEnv {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serde::Serialize::serialize(&self.0, serializer)
	}
}

impl<'de> serde::Deserialize<'de> for PivotEnv {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let env =
			<BTreeMap<PivotEnvVarName, PivotEnvValue> as serde::Deserialize>::deserialize(
				deserializer,
			)?;
		Self::try_from(env).map_err(serde::de::Error::custom)
	}
}

impl fmt::Debug for PivotEnv {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl PivotEnv {
	fn check_aggregate_limits(&self) -> Result<(), ProtocolError> {
		if self.len() > MAX_PIVOT_ENV_VARS {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"too many env vars: {} > {}",
				self.len(),
				MAX_PIVOT_ENV_VARS
			)));
		}

		let mut total_len = 0usize;
		for (name, value) in self.iter() {
			let plain_value = value.as_plain_value().ok_or_else(|| {
				ProtocolError::InvalidPivotEnv(format!(
					"env var `{name}` cannot be injected as plain text"
				))
			})?;
			total_len = total_len
				.checked_add(name.as_str().len())
				.and_then(|len| len.checked_add(plain_value.len()))
				.ok_or_else(|| {
					ProtocolError::InvalidPivotEnv(
						"env var payload length overflowed".to_string(),
					)
				})?;
		}

		if total_len > MAX_PIVOT_ENV_TOTAL_LEN {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"env var payload too large: {total_len} > {MAX_PIVOT_ENV_TOTAL_LEN}"
			)));
		}

		Ok(())
	}
}
