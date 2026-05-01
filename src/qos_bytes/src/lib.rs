//! Raw byte wrappers that format as hex.

use std::{borrow::Borrow, fmt};

/// Owned raw bytes that format as lowercase hex.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
	/// Decode owned bytes from a hex string.
	pub fn from_hex(raw_s: &str) -> Result<Self, qos_hex::HexError> {
		qos_hex::decode(raw_s).map(Self)
	}

	/// Borrow the wrapped raw bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Borrow the wrapped raw bytes mutably.
	#[must_use]
	pub fn as_mut_bytes(&mut self) -> &mut [u8] {
		&mut self.0
	}

	/// Return the wrapped byte length.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Return true if the wrapper contains no bytes.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Encode the wrapped bytes as lowercase hex.
	#[must_use]
	pub fn to_hex(&self) -> String {
		qos_hex::encode(&self.0)
	}

	/// Return the wrapped raw bytes.
	#[must_use]
	pub fn into_inner(self) -> Vec<u8> {
		self.0
	}
}

impl fmt::Debug for HexBytes {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HexBytes({})", HexDisplay::new(self.as_bytes()))
	}
}

impl fmt::Display for HexBytes {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt_hex(self.as_bytes(), f)
	}
}

impl AsRef<[u8]> for HexBytes {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

impl AsMut<[u8]> for HexBytes {
	fn as_mut(&mut self) -> &mut [u8] {
		self.as_mut_bytes()
	}
}

impl Borrow<[u8]> for HexBytes {
	fn borrow(&self) -> &[u8] {
		self.as_bytes()
	}
}

impl From<Vec<u8>> for HexBytes {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes)
	}
}

impl From<HexBytes> for Vec<u8> {
	fn from(bytes: HexBytes) -> Self {
		bytes.into_inner()
	}
}

impl TryFrom<&str> for HexBytes {
	type Error = qos_hex::HexError;

	fn try_from(raw_s: &str) -> Result<Self, Self::Error> {
		Self::from_hex(raw_s)
	}
}

impl TryFrom<String> for HexBytes {
	type Error = qos_hex::HexError;

	fn try_from(raw_s: String) -> Result<Self, Self::Error> {
		Self::from_hex(&raw_s)
	}
}

impl PartialEq<Vec<u8>> for HexBytes {
	fn eq(&self, other: &Vec<u8>) -> bool {
		self.as_bytes() == other.as_slice()
	}
}

/// Owned fixed-size raw bytes that format as lowercase hex.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HexArray<const N: usize>([u8; N]);

impl<const N: usize> HexArray<N> {
	/// Decode fixed-size bytes from a hex string.
	pub fn from_hex(raw_s: &str) -> Result<Self, qos_hex::HexError> {
		let mut bytes = [0_u8; N];
		qos_hex::decode_to_buf(raw_s, &mut bytes)?;
		Ok(Self(bytes))
	}

	/// Borrow the wrapped raw bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Borrow the wrapped raw bytes mutably.
	#[must_use]
	pub fn as_mut_bytes(&mut self) -> &mut [u8] {
		&mut self.0
	}

	/// Return the wrapped byte length.
	#[must_use]
	pub const fn len(&self) -> usize {
		N
	}

	/// Return true if the wrapper contains no bytes.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		N == 0
	}

	/// Encode the wrapped bytes as lowercase hex.
	#[must_use]
	pub fn to_hex(&self) -> String {
		qos_hex::encode(&self.0)
	}

	/// Return the wrapped raw bytes.
	#[must_use]
	pub fn into_inner(self) -> [u8; N] {
		self.0
	}
}

impl<const N: usize> fmt::Debug for HexArray<N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HexArray({})", HexDisplay::new(self.as_bytes()))
	}
}

impl<const N: usize> fmt::Display for HexArray<N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt_hex(self.as_bytes(), f)
	}
}

impl<const N: usize> AsRef<[u8]> for HexArray<N> {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

impl<const N: usize> AsMut<[u8]> for HexArray<N> {
	fn as_mut(&mut self) -> &mut [u8] {
		self.as_mut_bytes()
	}
}

impl<const N: usize> Borrow<[u8]> for HexArray<N> {
	fn borrow(&self) -> &[u8] {
		self.as_bytes()
	}
}

impl<const N: usize> From<[u8; N]> for HexArray<N> {
	fn from(bytes: [u8; N]) -> Self {
		Self(bytes)
	}
}

impl<const N: usize> From<HexArray<N>> for [u8; N] {
	fn from(bytes: HexArray<N>) -> Self {
		bytes.into_inner()
	}
}

impl<const N: usize> From<HexArray<N>> for HexBytes {
	fn from(bytes: HexArray<N>) -> Self {
		Self(bytes.as_bytes().to_vec())
	}
}

impl<const N: usize> TryFrom<&str> for HexArray<N> {
	type Error = qos_hex::HexError;

	fn try_from(raw_s: &str) -> Result<Self, Self::Error> {
		Self::from_hex(raw_s)
	}
}

impl<const N: usize> TryFrom<String> for HexArray<N> {
	type Error = qos_hex::HexError;

	fn try_from(raw_s: String) -> Result<Self, Self::Error> {
		Self::from_hex(&raw_s)
	}
}

impl<const N: usize> PartialEq<[u8; N]> for HexArray<N> {
	fn eq(&self, other: &[u8; N]) -> bool {
		self.as_bytes() == other
	}
}

/// Borrowed bytes formatted as lowercase hex.
#[derive(Clone, Copy)]
pub struct HexDisplay<'a>(&'a [u8]);

impl<'a> HexDisplay<'a> {
	/// Create a borrowed hex formatter.
	#[must_use]
	pub const fn new(bytes: &'a [u8]) -> Self {
		Self(bytes)
	}
}

impl fmt::Debug for HexDisplay<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HexDisplay({self})")
	}
}

impl fmt::Display for HexDisplay<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt_hex(self.0, f)
	}
}

/// Format borrowed bytes as lowercase hex.
#[must_use]
pub const fn hex_display(bytes: &[u8]) -> HexDisplay<'_> {
	HexDisplay::new(bytes)
}

fn fmt_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
	for byte in bytes {
		write!(f, "{byte:02x}")?;
	}
	Ok(())
}

#[cfg(feature = "serde")]
mod serde_impl {
	use core::{fmt, marker::PhantomData};

	use serde::{
		de::{Error, Visitor},
		Deserialize, Deserializer, Serialize, Serializer,
	};

	use super::{HexArray, HexBytes};

	impl Serialize for HexBytes {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.serialize_str(&self.to_hex())
		}
	}

	impl<'de> Deserialize<'de> for HexBytes {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			deserializer.deserialize_str(HexVisitor::<Self>(PhantomData))
		}
	}

	impl<const N: usize> Serialize for HexArray<N> {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.serialize_str(&self.to_hex())
		}
	}

	impl<'de, const N: usize> Deserialize<'de> for HexArray<N> {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			deserializer.deserialize_str(HexVisitor::<Self>(PhantomData))
		}
	}

	trait FromHexString: Sized {
		fn from_hex_string(data: &str) -> Result<Self, qos_hex::HexError>;
	}

	impl FromHexString for HexBytes {
		fn from_hex_string(data: &str) -> Result<Self, qos_hex::HexError> {
			Self::from_hex(data)
		}
	}

	impl<const N: usize> FromHexString for HexArray<N> {
		fn from_hex_string(data: &str) -> Result<Self, qos_hex::HexError> {
			Self::from_hex(data)
		}
	}

	struct HexVisitor<T>(PhantomData<T>);

	impl<T> Visitor<'_> for HexVisitor<T>
	where
		T: FromHexString,
	{
		type Value = T;

		fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			write!(f, "a hex encoded string")
		}

		fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
		where
			E: Error,
		{
			T::from_hex_string(data).map_err(|e| E::custom(format!("{e:?}")))
		}

		fn visit_borrowed_str<E>(self, data: &str) -> Result<Self::Value, E>
		where
			E: Error,
		{
			T::from_hex_string(data).map_err(|e| E::custom(format!("{e:?}")))
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn hex_bytes_formats_and_exposes_raw_bytes() {
		let bytes = HexBytes::from(vec![0, 15, 16, 255]);

		assert_eq!(bytes.as_bytes(), &[0, 15, 16, 255]);
		assert_eq!(bytes.as_ref(), &[0, 15, 16, 255]);
		assert_eq!(bytes.len(), 4);
		assert!(!bytes.is_empty());
		assert_eq!(bytes.to_hex(), "000f10ff");
		assert_eq!(format!("{bytes}"), "000f10ff");
		assert_eq!(format!("{bytes:?}"), "HexBytes(000f10ff)");
		assert_eq!(bytes, vec![0, 15, 16, 255]);
		assert_eq!(Vec::<u8>::from(bytes), vec![0, 15, 16, 255]);
	}

	#[test]
	fn hex_bytes_decodes_from_hex() {
		let bytes = HexBytes::from_hex("0x000f10ff").unwrap();

		assert_eq!(bytes.into_inner(), vec![0, 15, 16, 255]);
		assert_eq!(
			HexBytes::from_hex("abc").unwrap_err(),
			qos_hex::HexError::OddLength
		);
	}

	#[test]
	fn hex_array_formats_and_exposes_raw_bytes() {
		let bytes = HexArray::from([0, 15, 16, 255]);

		assert_eq!(bytes.as_bytes(), &[0, 15, 16, 255]);
		assert_eq!(bytes.as_ref(), &[0, 15, 16, 255]);
		assert_eq!(bytes.len(), 4);
		assert!(!bytes.is_empty());
		assert_eq!(bytes.to_hex(), "000f10ff");
		assert_eq!(format!("{bytes}"), "000f10ff");
		assert_eq!(format!("{bytes:?}"), "HexArray(000f10ff)");
		assert_eq!(bytes, [0, 15, 16, 255]);
		assert_eq!(<[u8; 4]>::from(bytes), [0, 15, 16, 255]);
	}

	#[test]
	fn hex_array_decodes_from_hex() {
		let bytes = HexArray::<4>::from_hex("0x000f10ff").unwrap();

		assert_eq!(bytes.into_inner(), [0, 15, 16, 255]);
		assert_eq!(
			HexArray::<4>::from_hex("000f10").unwrap_err(),
			qos_hex::HexError::StringDoesNotMatchBufferLength
		);
	}

	#[test]
	fn hex_array_converts_to_hex_bytes() {
		let bytes = HexArray::from([0, 15, 16, 255]);

		assert_eq!(HexBytes::from(bytes).into_inner(), vec![0, 15, 16, 255]);
	}

	#[test]
	fn hex_display_formats_borrowed_bytes() {
		let bytes = [0, 15, 16, 255];
		let display = HexDisplay::new(&bytes);

		assert_eq!(format!("{display}"), "000f10ff");
		assert_eq!(format!("{display:?}"), "HexDisplay(000f10ff)");
		assert_eq!(hex_display(&bytes).to_string(), "000f10ff");
	}

	#[cfg(feature = "serde")]
	#[test]
	fn hex_bytes_serde_uses_hex_string() {
		let bytes = HexBytes::from(vec![0, 15, 16, 255]);

		assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"000f10ff\"");
		assert_eq!(
			serde_json::from_str::<HexBytes>("\"0x000f10ff\"").unwrap(),
			vec![0, 15, 16, 255]
		);
	}

	#[cfg(feature = "serde")]
	#[test]
	fn hex_array_serde_uses_hex_string() {
		let bytes = HexArray::from([0, 15, 16, 255]);

		assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"000f10ff\"");
		assert_eq!(
			serde_json::from_str::<HexArray<4>>("\"0x000f10ff\"").unwrap(),
			[0, 15, 16, 255]
		);
		assert!(serde_json::from_str::<HexArray<4>>("\"000f10\"").is_err());
	}
}
