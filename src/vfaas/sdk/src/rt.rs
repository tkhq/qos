//! WASM-side runtime support for `#[program]` / `#[policy]`. All items are
//! `#[doc(hidden)]`: authors never reference them directly.
//!
//! Design notes:
//! - **Provenance tracking**: every `alloc` records `(ptr, len)` in
//!   `ALLOCATIONS`. `take_input` recovers the length from the map rather
//!   than trusting the host-supplied `len` blindly, so a malformed host
//!   call can't induce out-of-bounds reads of guest memory.
//! - **Universal host-to-guest passing**: the host always allocates via the
//!   exported `alloc` and writes bytes there; the guest reads via
//!   `take_input(ptr, host_len)`.
//! - **Packed return**: outputs are written into a fresh allocation and the
//!   `(ptr << 32) | len` packed `u64` is returned to the host. Avoids a
//!   second host import call.
//! - Single-threaded WASM: a plain `Mutex` is contention-free.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Map of guest-allocated pointers to their lengths. Populated by [`alloc`],
/// consulted by [`take_input`].
fn allocations() -> &'static Mutex<HashMap<u32, u32>> {
	static MAP: OnceLock<Mutex<HashMap<u32, u32>>> = OnceLock::new();
	MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Allocate `len` bytes in the guest's linear memory and return the offset.
/// Exported as `alloc` on the WASM side so the host can stage input bytes.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: u32) -> u32 {
	let mut buf = Vec::<u8>::with_capacity(len as usize);
	let ptr = buf.as_mut_ptr() as u32;
	core::mem::forget(buf);
	allocations()
		.lock()
		.expect("vfaas: ALLOCATIONS poisoned")
		.insert(ptr, len);
	ptr
}

/// Consume a host-provided `(ptr, host_len)` pair and return the input bytes.
///
/// Verifies that `ptr` was previously returned by [`alloc`] (provenance
/// check) and that the host-supplied length matches what we recorded. The
/// returned `Vec<u8>` owns the memory; the entry is removed from
/// `ALLOCATIONS`.
pub fn take_input(ptr: u32, host_len: u32) -> Vec<u8> {
	let len = allocations()
		.lock()
		.expect("vfaas: ALLOCATIONS poisoned")
		.remove(&ptr)
		.expect("vfaas: host passed an unknown pointer");
	assert_eq!(
		len, host_len,
		"vfaas: host length {host_len} disagrees with allocation length {len}"
	);
	// Safety: we allocated this pointer with Vec::with_capacity(len), forgot
	// the Vec, and now reconstruct it with the same capacity and length.
	// Same allocator, same layout.
	unsafe { Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize) }
}

/// Borsh deserialize a slice. Thin wrapper so the macro doesn't have to
/// emit a `borsh::` path with the right traits in scope.
///
/// # Errors
///
/// Returns [`borsh::io::Error`] if the bytes are not valid Borsh for `T`.
pub fn borsh_from_slice<T: borsh::BorshDeserialize>(
	bytes: &[u8],
) -> Result<T, borsh::io::Error> {
	T::try_from_slice(bytes)
}

/// Borsh serialize a value. Thin wrapper, see [`borsh_from_slice`].
///
/// # Errors
///
/// Returns [`borsh::io::Error`] if serialization fails (rare for owned data).
pub fn borsh_to_vec<T: borsh::BorshSerialize>(
	value: &T,
) -> Result<Vec<u8>, borsh::io::Error> {
	borsh::to_vec(value)
}

/// Allocate space for `bytes` in linear memory, copy the bytes in, and return
/// the packed `(ptr << 32) | len` value the host expects from the entrypoint.
#[must_use]
pub fn pack_result(bytes: Vec<u8>) -> u64 {
	let len = bytes.len() as u32;
	let ptr = alloc(len);
	// Safety: alloc() just gave us a fresh, exclusive allocation of `len`
	// bytes; copying `len` bytes into it is in-bounds.
	unsafe {
		std::ptr::copy_nonoverlapping(
			bytes.as_ptr(),
			ptr as *mut u8,
			len as usize,
		);
	}
	(u64::from(ptr) << 32) | u64::from(len)
}

/// Install a panic hook that writes the panic message to a known location so
/// the host can surface it. For now this is a no-op; the place to hook in
/// improved panic reporting later.
pub fn install_panic_hook() {
	// Intentional no-op for v1. Panics in the guest still abort the WASM
	// instance, which the host translates into a Failed outcome.
}
