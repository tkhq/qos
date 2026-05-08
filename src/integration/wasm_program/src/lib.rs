//! Example WASM program module for the pivot_wasm app.
//!
//! A program is the computation that runs after the policy approves it.
//! Unlike the policy, the program binary is NOT signed by the owner — anyone
//! can submit any program. The policy is the trust boundary that decides
//! whether a given program + input combination is allowed to execute.
//!
//! ## This example
//!
//! Reverses the input bytes. A trivial transformation to prove the execution
//! pipeline works end-to-end.

#![cfg_attr(target_arch = "wasm32", no_std)]

/// Reverse the input bytes and return them.
#[no_mangle]
pub extern "C" fn execute(ptr: i32, len: i32) -> i64 {
	let input =
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
	let out_len = len as usize;
	let result_ptr = wasm_rt::bump_alloc(out_len);

	let result =
		unsafe { core::slice::from_raw_parts_mut(result_ptr, out_len) };
	for (i, byte) in input.iter().enumerate() {
		result[out_len - 1 - i] = *byte;
	}

	wasm_rt::pack_result(result_ptr, out_len)
}
