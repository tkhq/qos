//! Integration tests.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

/// Path to the file `pivot_ok` writes on success for tests.
pub const PIVOT_OK_SUCCESS_FILE: &str = "./pivot_ok_works";
/// Path to pivot_ok bin for tests.
pub const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
/// Path to pivot_abort bin for tests.
pub const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";