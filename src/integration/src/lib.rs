//! Integration tests.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use qos_core::parser::{GetParserForOptions, OptionsParser, Parser, Token};

/// Path to the file `pivot_ok` writes on success for tests.
pub const PIVOT_OK_SUCCESS_FILE: &str = "./pivot_ok_works";
/// Path to the file `pivot_ok2` writes on success for tests.
pub const PIVOT_OK2_SUCCESS_FILE: &str = "./pivot_ok2_works";
/// Path to the file `pivot_ok3` writes on success for tests.
pub const PIVOT_OK3_SUCCESS_FILE: &str = "./pivot_ok3_works";
/// Path to pivot_ok bin for tests.
pub const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
/// Path to pivot_ok2 bin for tests.
pub const PIVOT_OK2_PATH: &str = "../target/debug/pivot_ok2";
/// Path to pivot_ok3 bin for tests.
pub const PIVOT_OK3_PATH: &str = "../target/debug/pivot_ok3";
/// Path to pivot_abort bin for tests.
pub const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";
/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";

const MSG: &str = "msg";

struct PivotParser;
impl GetParserForOptions for PivotParser {
	fn parser() -> Parser {
		Parser::new().token(
			Token::new(MSG, "A msg to write").takes_value(true).required(true),
		)
	}
}

/// Simple pivot CLI.
pub struct Cli;
impl Cli {
	/// Execute the CLI.
	pub fn execute(path: &str) {
		for i in 0..3 {
			std::thread::sleep(std::time::Duration::from_millis(i));
		}

		let mut args: Vec<String> = std::env::args().collect();
		let opts = OptionsParser::<PivotParser>::parse(&mut args)
			.expect("Entered invalid CLI args");

		let msg = opts.single(MSG).expect("required argument.");

		std::fs::write(path, msg).expect("Failed to write to pivot success");
	}
}
