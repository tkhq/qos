//! Example WASM policy module for the pivot_wasm app.
//!
//! A policy decides whether a given (program, input) pair is allowed to execute.
//! The pivot app verifies the owner's signature over the policy hash before
//! running it, so only owner-approved policies can gate execution.
//!
//! ## Policy input format
//!
//! The pivot app prepends the full program binary to the user input:
//!
//!   `program_wasm_len (4 bytes LE) || program_wasm || user_input`
//!
//! This gives the policy access to the raw program WASM bytecode so it can
//! inspect instructions, not just a hash.
//!
//! ## Policy output
//!
//! Single byte: `[1]` = allow, `[0]` (or anything else) = deny.
//!
//! ## This example
//!
//! Trivially allows execution if both the program binary and user input are
//! non-empty. A real policy could parse the WASM binary, check an allowlist
//! of program hashes, validate input structure, etc.

#![cfg_attr(target_arch = "wasm32", no_std)]

/// Input format: program_wasm_len (4 bytes LE) || program_wasm || user_input
///
/// Policy: allow if both program_wasm and user_input are non-empty.
/// Returns [1] for allow, [0] for deny.
#[no_mangle]
pub extern "C" fn execute(ptr: i32, len: i32) -> i64 {
	let input =
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };

	let allowed = if input.len() < 4 {
		false
	} else {
		let program_len =
			u32::from_le_bytes([input[0], input[1], input[2], input[3]])
				as usize;
		let has_program = program_len > 0;
		let has_input = input.len() > 4 + program_len;
		has_program && has_input
	};

	let result_byte: u8 = if allowed { 1 } else { 0 };
	let result_ptr = wasm_rt::bump_alloc(1);
	unsafe { *result_ptr = result_byte };

	wasm_rt::pack_result(result_ptr, 1)
}
