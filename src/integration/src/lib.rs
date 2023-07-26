//! Integration tests.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
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
/// Path to pivot loop bin for tests.
pub const PIVOT_LOOP_PATH: &str = "../target/debug/pivot_loop";
/// Path to pivot_abort bin for tests.
pub const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";
/// Path to an enclave app that has routes to stress our socket.
pub const PIVOT_SOCKET_STRESS_PATH: &str =
	"../target/debug/pivot_socket_stress";
/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";
/// PCR3 image associated with the preimage in `./mock/pcr3-preimage.txt`.
pub const PCR3: &str = "78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6";
/// QOS dist directory.
pub const QOS_DIST_DIR: &str = "../../dist";

const MSG: &str = "msg";

/// Request/Response messages for "socket stress" pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotSocketStressMsg {
	/// Request a [`Self::OkResponse`].
	OkRequest,
	/// A successful response to [`Self::OkRequest`].
	OkResponse,
	/// Request the app to panic. Does not have a response.
	PanicRequest,
	/// Request a response that will be slower then
	/// `ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS`.
	SlowRequest,
	/// Response to [`Self::SlowRequest`].
	SlowResponse,
}

struct PivotParser;
impl GetParserForOptions for PivotParser {
	fn parser() -> Parser {
		Parser::new().token(
			Token::new(MSG, "A msg to write").takes_value(true).required(true),
		)
	}
}

/// CLI options for pivot
#[derive(Clone, Debug, PartialEq)]
pub struct PivotOptions {
	parsed: Parser,
}

impl PivotOptions {
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<PivotParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
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
		let opts = PivotOptions::new(&mut args);

		let msg = opts.parsed.single(MSG).expect("required argument.");

		std::fs::write(path, msg).expect("Failed to write to pivot success");
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_is_idempotent() {
		let mut args: Vec<_> = vec!["binary", "--msg", "vape time"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = PivotOptions::new(&mut args);
		let opts2 = PivotOptions::new(&mut args);
		let parsed_args: Vec<_> =
			vec!["--msg", "vape time"].into_iter().map(String::from).collect();

		assert_eq!(args, parsed_args);
		assert_eq!(*opts.parsed.single(MSG).unwrap(), "vape time".to_string());
		assert_eq!(*opts2.parsed.single(MSG).unwrap(), "vape time".to_string());
	}
}
