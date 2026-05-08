//! Minimal WASM runtime support for pivot_wasm modules.
//!
//! Provides a bump allocator and the `alloc`/`dealloc` ABI exports so that
//! WASM policy and program crates only need to implement `execute`.

#![cfg_attr(target_arch = "wasm32", no_std)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

struct BumpAllocator {
	arena: UnsafeCell<[u8; 65536]>,
	offset: AtomicUsize,
}

// SAFETY: WASM is single-threaded. Required because UnsafeCell is !Sync
// and static values must be Sync.
unsafe impl Sync for BumpAllocator {}

static ALLOCATOR: BumpAllocator = BumpAllocator {
	arena: UnsafeCell::new([0u8; 65536]),
	offset: AtomicUsize::new(0),
};

/// Allocate `len` bytes from the bump allocator. Returns a pointer into
/// linear memory, or null on overflow.
pub fn bump_alloc(len: usize) -> *mut u8 {
	let offset = ALLOCATOR.offset.fetch_add(len, Ordering::SeqCst);
	if offset + len > 65536 {
		return core::ptr::null_mut();
	}
	unsafe { (*ALLOCATOR.arena.get()).as_mut_ptr().add(offset) }
}

/// Pack a (pointer, length) pair into the i64 return format expected by
/// the pivot_wasm host: `(ptr << 32) | len`.
pub fn pack_result(ptr: *const u8, len: usize) -> i64 {
	((ptr as i64) << 32) | (len as i64)
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
	bump_alloc(len as usize) as i32
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: i32, _len: i32) {}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}
