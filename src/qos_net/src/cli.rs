//! CLI for running a host proxy to provide remote connections.

use std::env;

use qos_core::{
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
	server::SocketServer,
};

use crate::processor::Processor;

/// "cid"
pub const CID: &str = "cid";
/// "port"
pub const PORT: &str = "port";
/// "usock"
pub const USOCK: &str = "usock";

/// CLI options for starting up the enclave server.
#[derive(Default, Clone, Debug, PartialEq)]
struct ProxyOpts {
	parsed: Parser,
}

impl ProxyOpts {
	/// Create a new instance of [`Self`] with some defaults.
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<ProxyParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Get the `SocketAddress` for the proxy server.
	///
	/// # Panics
	///
	/// Panics if the opts are not valid for exactly one of unix or vsock.
	fn addr(&self) -> SocketAddress {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => SocketAddress::new_vsock(
				c.parse::<u32>().unwrap(),
				p.parse::<u32>().unwrap(),
				crate::io::VMADDR_NO_FLAGS,
			),
			(None, None, Some(u)) => SocketAddress::new_unix(u),
			_ => panic!("Invalid socket opts"),
		}
	}
}

/// Enclave server CLI.
pub struct CLI;
impl CLI {
	/// Execute the enclave server CLI with the environment args.
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let opts = ProxyOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			SocketServer::listen(opts.addr(), Processor::new()).unwrap();
		}
	}
}

/// Parser for proxy CLI
struct ProxyParser;
impl GetParserForOptions for ProxyParser {
	fn parser() -> Parser {
		Parser::new()
			.token(
				Token::new(CID, "cid of the VSOCK the proxy should listen on.")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(PORT),
			)
			.token(
				Token::new(
					PORT,
					"port of the VSOCK the proxy should listen on.",
				)
				.takes_value(true)
				.forbids(vec![USOCK])
				.requires(CID),
			)
			.token(
				Token::new(USOCK, "unix socket (`.sock`) to listen on.")
					.takes_value(true)
					.forbids(vec!["port", "cid"]),
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
		let opts: ProxyOpts = ProxyOpts::new(&mut args);

		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
	}
	#[test]
	fn parse_usock() {
		let mut args: Vec<_> = vec!["binary", "--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = ProxyOpts::new(&mut args);

		assert_eq!(opts.addr(), SocketAddress::new_unix("./test.sock"));
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MutuallyExclusiveInput(\"cid\", \"usock\")"]
	fn panic_on_too_many_opts() {
		let mut args: Vec<_> = vec![
			"binary", "--cid", "6", "--port", "3999", "--usock", "my.sock",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let _opts = ProxyOpts::new(&mut args);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MissingInput(\"port\")"]
	fn panic_on_not_enough_opts() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6"]
			.into_iter()
			.map(String::from)
			.collect();
		let _opts = ProxyOpts::new(&mut args);
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(
			opts.addr(),
			SocketAddress::new_vsock(6, 3999, crate::io::VMADDR_NO_FLAGS)
		);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: UnexpectedInput(\"--derp\")"]
	fn panic_when_mistyped_cid() {
		let mut args: Vec<_> =
			vec!["--derp"].into_iter().map(String::from).collect();
		let _opts = ProxyOpts::new(&mut args);
	}
}
