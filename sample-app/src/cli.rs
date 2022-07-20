//! CLI for the sample app

use qos_core::{
	cli::{
		EPHEMERAL_FILE_OPT, MANIFEST_FILE_OPT, PIVOT_FILE_OPT, QUORUM_FILE_OPT,
		USOCK,
	},
	handles::Handles,
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
	server::SocketServer,
	EPHEMERAL_KEY_FILE, QUORUM_FILE, SEC_APP_SOCK,
};

const DEFAULT_PIVOT_PATH: &str = "./target/release/sample-app";

/// CLI options for starting up the app server.
#[derive(Default, Clone, Debug, PartialEq)]
struct AppOpts {
	parsed: Parser,
}

impl AppOpts {
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<AppParser>::parse(args)
			.expect("Sample App: Entered invalid CLI args");

		Self { parsed }
	}

	fn addr(&self) -> SocketAddress {
		SocketAddress::new_unix(
			self.parsed.single(USOCK).expect("Unix socket is required"),
		)
	}

	fn quorum_file(&self) -> String {
		self.parsed
			.single(QUORUM_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	fn pivot_file(&self) -> String {
		self.parsed
			.single(PIVOT_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	fn ephemeral_file(&self) -> String {
		self.parsed
			.single(EPHEMERAL_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	fn manifest_file(&self) -> String {
		self.parsed
			.single(MANIFEST_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}
}

/// Parser for the app CLI.
struct AppParser;
impl GetParserForOptions for AppParser {
	fn parser() -> Parser {
		Parser::new().token(
			Token::new(USOCK, "unix socket (`.sock`) to listen on.")
				.takes_value(true)
				.forbids(vec!["port", "cid"])
				.default_value(SEC_APP_SOCK),
		)
		.token(
			Token::new(QUORUM_FILE_OPT, "path to file where the Quorum Key secret should be stored. Use default for production.")
				.takes_value(true)
				.default_value(QUORUM_FILE)
		)
		.token(
			Token::new(EPHEMERAL_FILE_OPT, "path to file where the Ephemeral Key secret should be written. Use default for production.")
				.takes_value(true)
				.default_value(EPHEMERAL_KEY_FILE)
		)
		.token(
			Token::new(MANIFEST_FILE_OPT, "path to file where the Manifest should be written. Use default for production")
				.takes_value(true)
				.default_value(MANIFEST_FILE_OPT)
		)
		.token(
			Token::new(PIVOT_FILE_OPT, "path to file where the Pivot Binary should be written. Use default for production.")
				.takes_value(true)
				.default_value(DEFAULT_PIVOT_PATH),
		)
	}
}

/// Sample App CLI.
pub struct Cli;
impl Cli {
	/// Execute the CLI.
	///
	/// # Panics
	///
	/// Panics if the socket server errors.
	pub fn execute() {
		let mut args: Vec<String> = std::env::args().collect();

		let opts = AppOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			let processor = super::AppProcessor::new(Handles::new(
				opts.ephemeral_file(),
				opts.quorum_file(),
				opts.manifest_file(),
				opts.pivot_file(),
			));
			println!("---- Starting secure app server -----");

			SocketServer::listen(opts.addr(), processor).unwrap();
		}
	}
}
