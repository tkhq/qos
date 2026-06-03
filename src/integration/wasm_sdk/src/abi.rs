//! WASM ABI glue.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

use borsh::BorshDeserialize;

use crate::{Decision, PolicyContext};

const ARENA_LEN: usize = 1024 * 1024;

struct BumpAllocator {
	arena: UnsafeCell<[u8; ARENA_LEN]>,
	offset: AtomicUsize,
}

unsafe impl Sync for BumpAllocator {}

static ALLOCATOR: BumpAllocator = BumpAllocator {
	arena: UnsafeCell::new([0u8; ARENA_LEN]),
	offset: AtomicUsize::new(0),
};

pub fn bump_alloc(len: usize) -> *mut u8 {
	let offset = ALLOCATOR.offset.fetch_add(len, Ordering::SeqCst);
	if offset.checked_add(len).is_none_or(|end| end > ARENA_LEN) {
		return std::ptr::null_mut();
	}
	unsafe { (*ALLOCATOR.arena.get()).as_mut_ptr().add(offset) }
}

pub fn pack_result(ptr: *const u8, len: usize) -> i64 {
	((ptr as i64) << 32) | (len as i64)
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
	if len < 0 {
		return 0;
	}
	bump_alloc(len as usize) as i32
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: i32, _len: i32) {}

pub fn function_entry<F>(ptr: i32, len: i32, function: F) -> i64
where
	F: Fn(Vec<u8>) -> Vec<u8>,
{
	let input = read_input(ptr, len);
	let output = function(input);
	write_output(&output)
}

pub fn policy_entry<F>(ptr: i32, len: i32, policy: F) -> i64
where
	F: Fn(PolicyContext) -> Decision,
{
	let input = read_input(ptr, len);
	let decision = match PolicyContext::try_from_slice(&input) {
		Ok(context) => policy(context),
		Err(e) => Decision::deny(format!("invalid policy context: {e}")),
	};
	let output = borsh::to_vec(&decision).unwrap_or_else(|_| {
		borsh::to_vec(&Decision::deny("failed to encode policy decision"))
			.expect("fallback decision serializes")
	});
	write_output(&output)
}

fn read_input(ptr: i32, len: i32) -> Vec<u8> {
	if ptr < 0 || len <= 0 {
		return Vec::new();
	}
	let bytes =
		unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
	bytes.to_vec()
}

fn write_output(output: &[u8]) -> i64 {
	let ptr = bump_alloc(output.len());
	if ptr.is_null() && !output.is_empty() {
		return pack_result(std::ptr::null(), 0);
	}
	unsafe {
		std::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
	}
	pack_result(ptr, output.len())
}
