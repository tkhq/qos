//! Pivot environment variable manifest types.

use std::{borrow::Borrow, collections::BTreeMap, fmt, ops::Deref};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::protocol::ProtocolError;

/// Maximum number of env vars in a pivot manifest.
pub const MAX_PIVOT_ENV_VARS: usize = 512;
/// Maximum pivot env var name length in bytes.
pub const MAX_PIVOT_ENV_NAME_LEN: usize = 1024;
/// Maximum pivot env var value length in bytes.
pub const MAX_PIVOT_ENV_VALUE_LEN: usize = 64 * 1024;

/// Environment variable name to inject into the pivot process.
#[derive(
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Clone,
	Hash,
	Debug,
	BorshSerialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(try_from = "String")]
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
}

impl fmt::Display for PivotEnvVarName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl Borrow<str> for PivotEnvVarName {
	fn borrow(&self) -> &str {
		&self.0
	}
}

impl Deref for PivotEnvVarName {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl TryFrom<String> for PivotEnvVarName {
	type Error = ProtocolError;

	fn try_from(name: String) -> Result<Self, Self::Error> {
		Self::new(name)
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

/// Validated plain-text environment variable value.
#[derive(
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Clone,
	Hash,
	BorshSerialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(try_from = "String")]
pub struct PivotEnvPlainValue(String);

impl PivotEnvPlainValue {
	/// Parse and validate a plain environment variable value.
	pub fn new(value: String) -> Result<Self, ProtocolError> {
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

		Ok(Self(value))
	}
}

impl Deref for PivotEnvPlainValue {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl AsRef<str> for PivotEnvPlainValue {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for PivotEnvPlainValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl fmt::Debug for PivotEnvPlainValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl TryFrom<String> for PivotEnvPlainValue {
	type Error = ProtocolError;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::new(value)
	}
}

impl From<PivotEnvPlainValue> for String {
	fn from(value: PivotEnvPlainValue) -> Self {
		value.0
	}
}

impl BorshDeserialize for PivotEnvPlainValue {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let value = String::deserialize_reader(reader)?;
		Self::new(value).map_err(|e| {
			borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e)
		})
	}
}

/// Environment variable value to inject into the pivot process.
#[derive(
	PartialEq,
	Eq,
	Clone,
	Debug,
	BorshSerialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PivotEnvValue {
	/// A plain, non-secret environment variable value.
	Plain {
		/// Value to set for the environment variable.
		value: PivotEnvPlainValue,
	},
}

impl PivotEnvValue {
	/// Parse and validate a plain environment variable value.
	pub fn plain(value: String) -> Result<Self, ProtocolError> {
		Ok(Self::Plain { value: PivotEnvPlainValue::try_from(value)? })
	}

	/// Return the string value to inject into the pivot process.
	#[must_use]
	#[allow(unreachable_patterns)]
	pub fn as_plain_value(&self) -> Option<&str> {
		match self {
			Self::Plain { value } => Some(value.as_ref()),
			_ => None,
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

/// Environment variables to inject into the pivot process.
#[derive(
	PartialEq,
	Eq,
	Clone,
	Default,
	BorshSerialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(try_from = "BTreeMap<PivotEnvVarName, PivotEnvValue>")]
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

	/// Insert an environment variable.
	pub fn insert(
		&mut self,
		name: PivotEnvVarName,
		value: PivotEnvValue,
	) -> Result<Option<PivotEnvValue>, ProtocolError> {
		let previous = self.0.insert(name.clone(), value);
		if let Err(err) = self.check_limits() {
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

	fn check_limits(&self) -> Result<(), ProtocolError> {
		if self.len() > MAX_PIVOT_ENV_VARS {
			return Err(ProtocolError::InvalidPivotEnv(format!(
				"too many env vars: {} > {}",
				self.len(),
				MAX_PIVOT_ENV_VARS
			)));
		}
		Ok(())
	}
}

impl TryFrom<BTreeMap<PivotEnvVarName, PivotEnvValue>> for PivotEnv {
	type Error = ProtocolError;

	fn try_from(
		value: BTreeMap<PivotEnvVarName, PivotEnvValue>,
	) -> Result<Self, Self::Error> {
		let env = Self(value);
		env.check_limits()?;
		Ok(env)
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

impl fmt::Debug for PivotEnv {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl Deref for PivotEnv {
	type Target = BTreeMap<PivotEnvVarName, PivotEnvValue>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

#[cfg(test)]
mod test {
	use borsh::{BorshDeserialize, BorshSerialize};

	use super::*;

	#[test]
	fn parses_valid_pivot_env() {
		let mut env = BTreeMap::new();
		env.insert(
			PivotEnvVarName::new("FOO".to_string()).unwrap(),
			PivotEnvValue::plain("bar".to_string()).unwrap(),
		);
		env.insert(
			PivotEnvVarName::new("_EMPTY".to_string()).unwrap(),
			PivotEnvValue::plain(String::new()).unwrap(),
		);

		assert!(PivotEnv::try_from(env).is_ok());
	}

	#[test]
	fn accepts_valid_pivot_env_var_names() {
		assert!(PivotEnvVarName::new("A".to_string()).is_ok());
		assert!(PivotEnvVarName::new("_".to_string()).is_ok());
		assert!(PivotEnvVarName::new("_WITH_NUMBERS_123".to_string()).is_ok());
		assert!(
			PivotEnvVarName::new("A".repeat(MAX_PIVOT_ENV_NAME_LEN)).is_ok()
		);
	}

	#[test]
	fn rejects_invalid_pivot_env_as_it_parses() {
		assert!(PivotEnvVarName::new(String::new()).is_err());
		assert!(PivotEnvVarName::new("BAD=NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("1BAD".to_string()).is_err());
		assert!(PivotEnvVarName::new("BAD-NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("BAD.NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("BAD NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("BAD/NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("BAD+NAME".to_string()).is_err());
		assert!(PivotEnvVarName::new("A".repeat(MAX_PIVOT_ENV_NAME_LEN + 1))
			.is_err());
		assert!(PivotEnvValue::plain("bad\0value".to_string()).is_err());
		assert!(PivotEnvValue::plain("A".repeat(MAX_PIVOT_ENV_VALUE_LEN + 1))
			.is_err());

		let mut env = BTreeMap::new();
		for i in 0..=MAX_PIVOT_ENV_VARS {
			env.insert(
				PivotEnvVarName::new(format!("KEY_{i}")).unwrap(),
				PivotEnvValue::plain("value".to_string()).unwrap(),
			);
		}
		assert!(PivotEnv::try_from(env).is_err());
	}

	#[test]
	fn pivot_env_serializes_to_sorted_externally_tagged_json() {
		let mut env = PivotEnv::new();
		env.insert(
			PivotEnvVarName::new("ZETA".to_string()).unwrap(),
			PivotEnvValue::plain("last".to_string()).unwrap(),
		)
		.unwrap();
		env.insert(
			PivotEnvVarName::new("ALPHA".to_string()).unwrap(),
			PivotEnvValue::plain("first".to_string()).unwrap(),
		)
		.unwrap();

		let serialized = serde_json::to_string(&env).unwrap();
		assert_eq!(
			serialized,
			r#"{"ALPHA":{"plain":{"value":"first"}},"ZETA":{"plain":{"value":"last"}}}"#
		);
	}

	#[test]
	fn pivot_env_insert_rejects_values_that_exceed_count_limit() {
		let mut env = PivotEnv::new();
		for i in 0..MAX_PIVOT_ENV_VARS {
			env.insert(
				PivotEnvVarName::new(format!("KEY_{i}")).unwrap(),
				PivotEnvValue::plain("value".to_string()).unwrap(),
			)
			.unwrap();
		}

		let err = env
			.insert(
				PivotEnvVarName::new("ONE_TOO_MANY".to_string()).unwrap(),
				PivotEnvValue::plain("value".to_string()).unwrap(),
			)
			.unwrap_err();

		assert!(matches!(err, ProtocolError::InvalidPivotEnv(_)));
		assert_eq!(env.len(), MAX_PIVOT_ENV_VARS);
		assert!(env.get("ONE_TOO_MANY").is_none());
	}

	#[test]
	fn rejects_invalid_pivot_env_during_serde_deserialize() {
		let invalid = PivotEnv(BTreeMap::from([(
			PivotEnvVarName("1BAD".to_string()),
			PivotEnvValue::Plain {
				value: PivotEnvPlainValue("bar".to_string()),
			},
		)]));

		let serialized = serde_json::to_value(&invalid).unwrap();
		let err = serde_json::from_value::<PivotEnv>(serialized).unwrap_err();
		assert!(
			err.to_string()
				.contains("env var name `1BAD` must start with [A-Za-z_]"),
			"unexpected serde error: {err}"
		);
	}

	#[test]
	fn rejects_invalid_pivot_env_during_borsh_deserialize() {
		let mut bytes = Vec::new();
		1u32.serialize(&mut bytes).unwrap();
		"1BAD".to_string().serialize(&mut bytes).unwrap();
		0u8.serialize(&mut bytes).unwrap();
		"bar".to_string().serialize(&mut bytes).unwrap();

		let err = PivotEnv::try_from_slice(&bytes).unwrap_err();
		assert_eq!(err.kind(), borsh::io::ErrorKind::InvalidData);
		assert!(
			err.to_string()
				.contains("env var name `1BAD` must start with [A-Za-z_]"),
			"unexpected borsh error: {err}"
		);
	}
}
