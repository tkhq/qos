//! Heap-allocated secret byte buffers.

use std::ops::{Deref, DerefMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-length secret byte buffer that lives on the heap and is zeroized on
/// drop.
///
/// Moving a [`SecretBytes`] only copies the pointer, so the secret is not
/// duplicated on the stack. The buffer is private and there is no way to move
/// the array out, so the heap copy is always the one that gets wiped. Callers
/// should fill the buffer in place (via [`Self::zeroed`] and `DerefMut`, or
/// [`TryFrom<&[u8]>`]) rather than building an array and boxing it, since an
/// array built on the stack leaves a copy behind.
///
/// Dereferencing to `[u8; N]` and copying it out (`*secret`) leaves an
/// unzeroized copy, so only do that for non-secret values such as nonces.
pub struct SecretBytes<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
	/// Allocate a zeroed buffer on the heap.
	#[must_use]
	pub fn zeroed() -> Self {
		Self(Box::new([0u8; N]))
	}
}

impl<const N: usize> Deref for SecretBytes<N> {
	type Target = [u8; N];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl<const N: usize> DerefMut for SecretBytes<N> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl<const N: usize> From<&[u8; N]> for SecretBytes<N> {
	/// Copy `bytes` straight into a new heap buffer.
	fn from(bytes: &[u8; N]) -> Self {
		let mut secret = Self::zeroed();
		secret.copy_from_slice(bytes);
		secret
	}
}

impl<const N: usize> TryFrom<&[u8]> for SecretBytes<N> {
	type Error = std::array::TryFromSliceError;

	/// Copy `bytes` straight into a new heap buffer.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let bytes: &[u8; N] = bytes.try_into()?;
		let mut secret = Self::zeroed();
		secret.copy_from_slice(bytes);
		Ok(secret)
	}
}

impl<const N: usize> Clone for SecretBytes<N> {
	fn clone(&self) -> Self {
		let mut secret = Self::zeroed();
		secret.copy_from_slice(&self.0[..]);
		secret
	}
}

impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "SecretBytes<{N}>(REDACTED)")
	}
}

impl<const N: usize> Zeroize for SecretBytes<N> {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl<const N: usize> Drop for SecretBytes<N> {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

#[cfg(any(feature = "mock", test))]
impl<const N: usize> PartialEq for SecretBytes<N> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}

#[cfg(any(feature = "mock", test))]
impl<const N: usize> Eq for SecretBytes<N> {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn try_from_slice_checks_length() {
		let secret = SecretBytes::<4>::try_from(&[1u8, 2, 3, 4][..]).unwrap();
		assert_eq!(*secret, [1, 2, 3, 4]);

		assert!(SecretBytes::<4>::try_from(&[1u8, 2, 3][..]).is_err());
		assert!(SecretBytes::<4>::try_from(&[1u8, 2, 3, 4, 5][..]).is_err());
	}

	#[test]
	fn zeroize_wipes_the_heap_buffer() {
		let mut secret =
			SecretBytes::<4>::try_from(&[1u8, 2, 3, 4][..]).unwrap();
		secret.zeroize();
		assert_eq!(*secret, [0; 4]);
	}

	#[test]
	fn debug_is_redacted() {
		let secret = SecretBytes::<4>::from(&[0xAB; 4]);
		assert_eq!(format!("{secret:?}"), "SecretBytes<4>(REDACTED)");
	}
}
