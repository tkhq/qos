//! Integration tests.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use std::{net::TcpListener, ops::Range, thread, time::Duration};

use qos_core::parser::{GetParserForOptions, OptionsParser, Parser, Token};
use rand::prelude::*;

const MAX_PORT_BIND_WAIT_TIME: Duration = Duration::from_secs(90);
const PORT_BIND_WAIT_TIME_INCREMENT: Duration = Duration::from_millis(500);
const POST_BIND_SLEEP: Duration = Duration::from_millis(500);
const SERVER_PORT_RANGE: Range<u16> = 10000..60000;
const MAX_PORT_SEARCH_ATTEMPTS: u16 = 50;

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

/// Wrapper type for [`std::process::Child`] that kills the process on drop.
#[derive(Debug)]
pub struct ChildWrapper(std::process::Child);

impl From<std::process::Child> for ChildWrapper {
	fn from(child: std::process::Child) -> Self {
		Self(child)
	}
}

impl Drop for ChildWrapper {
	fn drop(&mut self) {
		// Kill the process and explicitly ignore the result
		drop(self.0.kill());
	}
}

/// Get a bind-able TCP port on the local system.
#[must_use]
pub fn find_free_port() -> Option<u16> {
	let mut rng = rand::thread_rng();
	for _ in 0..MAX_PORT_SEARCH_ATTEMPTS {
		let port = rng.gen_range(SERVER_PORT_RANGE);
		if port_is_available(port) {
			return Some(port);
		}
	}

	None
}

/// Wait until the given `port` is bound. Helpful for telling if something is
/// listening on the given port.
///
/// # Panics
///
/// Panics if the the port is not bound to within `MAX_PORT_BIND_WAIT_TIME`.
pub fn wait_until_port_is_bound(port: u16) {
	let mut wait_time = PORT_BIND_WAIT_TIME_INCREMENT;

	while wait_time < MAX_PORT_BIND_WAIT_TIME {
		thread::sleep(wait_time);
		if port_is_available(port) {
			wait_time += PORT_BIND_WAIT_TIME_INCREMENT;
		} else {
			thread::sleep(POST_BIND_SLEEP);
			return;
		}
	}
	panic!(
		"Server has not come up: port {} is still available after {}s",
		port,
		MAX_PORT_BIND_WAIT_TIME.as_secs()
	)
}

/// Return wether or not the port can be bind-ed too.
fn port_is_available(port: u16) -> bool {
	TcpListener::bind(("127.0.0.1", port)).is_ok()
}
