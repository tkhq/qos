//! CLI for running an enclave binary.

use std::env;

use crate::{
	coordinator::Coordinator,
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
	protocol::attestor::{Nsm, NsmProvider},
	EPHEMERAL_KEY_FILE, PIVOT_FILE, SECRET_FILE,
};

/// "cid"
pub const CID: &str = "cid";
/// "port"
pub const PORT: &str = "port";
/// "usock"
pub const USOCK: &str = "usock";
const MOCK: &str = "mock";
const SECRET_FILE_OPT: &str = "secret-file";
const PIVOT_FILE_OPT: &str = "pivot-file";
const EPHEMERAL_FILE_OPT: &str = "ephemeral-file";

/// CLI options for starting up the enclave server.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct EnclaveOptions {
	parsed: Parser,
}

impl EnclaveOptions {
	/// Create a new instance of [`Self`] with some defaults.
	#[must_use]
	pub fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<EnclaveParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Get the `SocketAddress` for the enclave server.
	///
	/// # Panics
	///
	/// Panics if the options are not valid for exactly one of unix or vsock.
	#[must_use]
	pub fn addr(&self) -> SocketAddress {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => SocketAddress::new_vsock(
				c.parse::<u32>().unwrap(),
				p.parse::<u32>().unwrap(),
			),
			#[cfg(feature = "local")]
			(None, None, Some(u)) => SocketAddress::new_unix(u),
			_ => panic!("Invalid socket options"),
		}
	}

	/// Get the [`NsmProvider`]
	#[must_use]
	pub fn nsm(&self) -> Box<dyn NsmProvider> {
		if self.parsed.flag(MOCK).unwrap_or(false) {
			#[cfg(feature = "mock")]
			{
				Box::new(crate::protocol::attestor::mock::MockNsm)
			}
			#[cfg(not(feature = "mock"))]
			{
				panic!("\"mock\" feature must be enabled to use `MockNsm`")
			}
		} else {
			Box::new(Nsm)
		}
	}

	/// Defaults to [`SECRET_FILE`] if not explicitly specified
	#[must_use]
	pub fn secret_file(&self) -> String {
		self.parsed
			.single(SECRET_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`PIVOT_FILE`] if not explicitly specified
	#[must_use]
	pub fn pivot_file(&self) -> String {
		self.parsed
			.single(PIVOT_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`EPHEMERAL_KEY_FILE`] if not explicitly specified
	#[must_use]
	pub fn ephemeral_file(&self) -> String {
		self.parsed
			.single(EPHEMERAL_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}
}

/// Enclave server CLI.
pub struct CLI {}
impl CLI {
	/// Execute the enclave server CLI with the environment args.
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let options = EnclaveOptions::new(&mut args);

		if options.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if options.parsed.help() {
			println!("{}", options.parsed.info());
		} else {
			Coordinator::execute(options);
		}
	}
}

/// Parser for enclave CLI
pub struct EnclaveParser;
impl GetParserForOptions for EnclaveParser {
	fn parser() -> Parser {
		Parser::new()
			.token(
				Token::new(CID, "cid of the VSOCK the enclave should listen on.")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(PORT),
			)
			.token(
				Token::new(PORT, "port of the VSOCK the enclave should listen on.")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(CID),
			)
			.token(
				Token::new(USOCK, "unix socket (`.sock`) to listen on.")
					.takes_value(true)
					.forbids(vec!["port", "cid"]),
			)
			.token(
				Token::new(MOCK, "include to use the mock Nitro Secure Module; helpful for local dev.")
			)
			.token(
				Token::new(SECRET_FILE_OPT, "path to file where the Quorum Key secret should be stored.")
					.takes_value(true)
					.default_value(SECRET_FILE)
			)
			.token(
				Token::new(PIVOT_FILE_OPT, "path to file where the Pivot Binary should be written.")
					.takes_value(true)
					.default_value(PIVOT_FILE),
			)
			.token(
				Token::new(EPHEMERAL_FILE_OPT, "path to file where the Ephemeral Key secret should be written.")
					.takes_value(true)
					.default_value(EPHEMERAL_KEY_FILE)
			)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_cid_and_port() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::new(&mut args);

		assert_eq!(*options.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*options.parsed.single(PORT).unwrap(), "3999".to_string());
	}

	#[test]
	fn parse_pivot_file_and_secret_file() {
		let pivot = "pivot.file";
		let secret = "secret.file";
		let ephemeral = "ephemeral.file";
		let mut args: Vec<_> = vec![
			"binary",
			"--cid",
			"6",
			"--port",
			"3999",
			"--secret-file",
			secret,
			"--pivot-file",
			pivot,
			"--ephemeral-file",
			ephemeral,
		]
		.into_iter()
		.map(String::from)
		.collect();
		let options = EnclaveOptions::new(&mut args);

		assert_eq!(*options.parsed.single(CID).unwrap(), "6");
		assert_eq!(*options.parsed.single(PORT).unwrap(), "3999");
		assert_eq!(options.secret_file(), secret);
		assert_eq!(options.pivot_file(), pivot);
		assert_eq!(options.ephemeral_file(), ephemeral);
	}

	#[test]
	fn parse_usock() {
		let mut args: Vec<_> = vec!["binary", "--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::new(&mut args);

		assert_eq!(options.addr(), SocketAddress::new_unix("./test.sock"));
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MutuallyExclusiveInput(\"cid\", \"usock\")"]
	fn panic_on_too_many_options() {
		let mut args: Vec<_> = vec![
			"binary", "--cid", "6", "--port", "3999", "--usock", "my.sock",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let _options = EnclaveOptions::new(&mut args);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MissingInput(\"port\")"]
	fn panic_on_not_enough_options() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = EnclaveOptions::new(&mut args);
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::new(&mut args);

		assert_eq!(options.addr(), SocketAddress::new_vsock(6, 3999));
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: UnexpectedInput(\"durp\")"]
	fn panic_when_mistyped_cid() {
		let mut args: Vec<_> =
			vec!["--usock", "durp"].into_iter().map(String::from).collect();
		let _options = EnclaveOptions::new(&mut args);
	}
}
