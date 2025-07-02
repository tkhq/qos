//! CLI for running an enclave binary.

use std::env;

use qos_nsm::{Nsm, NsmProvider};

use crate::{
	handles::Handles,
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
	reaper::Reaper,
	DEFAULT_POOL_SIZE, EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE,
	QUORUM_FILE, SEC_APP_SOCK,
};

#[cfg(feature = "async")]
use crate::io::AsyncStreamPool;

/// "cid"
pub const CID: &str = "cid";
/// "port"
pub const PORT: &str = "port";
/// "usock"
pub const USOCK: &str = "usock";
const MOCK: &str = "mock";
/// Name for the option to specify the quorum key file.
pub const QUORUM_FILE_OPT: &str = "quorum-file";
/// Name for the option to specify the pivot key file.
pub const PIVOT_FILE_OPT: &str = "pivot-file";
/// Name for the option to specify the ephemeral key file.
pub const EPHEMERAL_FILE_OPT: &str = "ephemeral-file";
/// Name for the option to specify the manifest file.
pub const MANIFEST_FILE_OPT: &str = "manifest-file";
const APP_USOCK: &str = "app-usock";
/// Name for the option to specify the maximum `AsyncPool` size.
pub const POOL_SIZE: &str = "pool-size";

/// CLI options for starting up the enclave server.
#[derive(Default, Clone, Debug, PartialEq)]
struct EnclaveOpts {
	parsed: Parser,
}

impl EnclaveOpts {
	/// Create a new instance of [`Self`] with some defaults.
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<EnclaveParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Create a new [`AsyncPool`] of [`AsyncStream`] using the list of [`SocketAddress`] for the enclave server and
	/// return the new [`AsyncPool`]. Analogous to [`Self::addr`] and [`Self::app_addr`] depending on the [`app`] parameter.
	#[cfg(feature = "async")]
	#[allow(unused)]
	fn async_pool(&self, app: bool) -> AsyncStreamPool {
		use nix::sys::time::{TimeVal, TimeValLike};

		let pool_size: u32 = self
			.parsed
			.single(POOL_SIZE)
			.expect("invalid pool options")
			.parse()
			.expect("invalid pool_size specified");
		let usock_param = if app { APP_USOCK } else { USOCK };

		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(usock_param),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => {
				let c = c.parse::<u32>().unwrap();
				let start_port = p.parse::<u32>().unwrap();

				let addresses = (start_port..start_port + pool_size).map(|p| {
					SocketAddress::new_vsock(c, p, crate::io::VMADDR_NO_FLAGS)
				});

				AsyncStreamPool::new(addresses, TimeVal::seconds(5))
			}
			(None, None, Some(u)) => {
				let addresses = (0..pool_size).map(|i| {
					let u = format!("{u}_{i}"); // add _X suffix for pooling
					SocketAddress::new_unix(&u)
				});

				AsyncStreamPool::new(addresses, TimeVal::seconds(5))
			}
			_ => panic!("Invalid socket opts"),
		}
	}

	/// Get the `SocketAddress` for the enclave server.
	///
	/// # Panics
	///
	/// Panics if the opts are not valid for exactly one of unix or vsock.
	#[allow(unused)]
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

	#[allow(unused)]
	fn app_addr(&self) -> SocketAddress {
		SocketAddress::new_unix(
			self.parsed
				.single(APP_USOCK)
				.expect("app-usock has a default value."),
		)
	}

	/// Get the [`NsmProvider`]
	fn nsm(&self) -> Box<dyn NsmProvider + Send> {
		if self.parsed.flag(MOCK).unwrap_or(false) {
			#[cfg(feature = "mock")]
			{
				Box::new(qos_nsm::mock::MockNsm)
			}
			#[cfg(not(feature = "mock"))]
			{
				panic!("\"mock\" feature must be enabled to use `MockNsm`")
			}
		} else {
			Box::new(Nsm)
		}
	}

	/// Defaults to [`QUORUM_FILE`] if not explicitly specified
	fn quorum_file(&self) -> String {
		self.parsed
			.single(QUORUM_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`PIVOT_FILE`] if not explicitly specified
	fn pivot_file(&self) -> String {
		self.parsed
			.single(PIVOT_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`EPHEMERAL_KEY_FILE`] if not explicitly specified
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

/// Enclave server CLI.
pub struct CLI;
impl CLI {
	/// Execute the enclave server CLI with the environment args.
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let opts = EnclaveOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			Reaper::execute(
				&Handles::new(
					opts.ephemeral_file(),
					opts.quorum_file(),
					opts.manifest_file(),
					opts.pivot_file(),
				),
				opts.nsm(),
				opts.addr(),
				opts.app_addr(),
				None,
			);
		}
	}

	/// Execute the enclave server CLI with the environment args using tokio/async
	#[cfg(feature = "async")]
	pub fn async_execute() {
		let mut args: Vec<String> = env::args().collect();
		let opts = EnclaveOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			Reaper::async_execute(
				&Handles::new(
					opts.ephemeral_file(),
					opts.quorum_file(),
					opts.manifest_file(),
					opts.pivot_file(),
				),
				opts.nsm(),
				opts.async_pool(false),
				opts.async_pool(true),
				None,
			);
		}
	}
}

/// Parser for enclave CLI
struct EnclaveParser;
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
				Token::new(QUORUM_FILE_OPT, "path to file where the Quorum Key secret should be stored. Use default for production.")
					.takes_value(true)
					.default_value(QUORUM_FILE)
			)
			.token(
				Token::new(PIVOT_FILE_OPT, "path to file where the Pivot Binary should be written. Use default for production.")
					.takes_value(true)
					.default_value(PIVOT_FILE),
			)
			.token(
				Token::new(EPHEMERAL_FILE_OPT, "path to file where the Ephemeral Key secret should be written. Use default for production.")
					.takes_value(true)
					.default_value(EPHEMERAL_KEY_FILE)
			)
			.token(
				Token::new(MANIFEST_FILE_OPT, "path to file where the Manifest should be written. Use default for production")
					.takes_value(true)
					.default_value(MANIFEST_FILE)
			)
			.token(
				Token::new(APP_USOCK, "the socket the secure app is listening on.")
					.takes_value(true)
					.default_value(SEC_APP_SOCK)
			)
			.token(
				Token::new(POOL_SIZE, "the pool size for use with all socket types")
					.takes_value(true)
					.default_value(DEFAULT_POOL_SIZE)
			)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_is_idempotent() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);
		let opts2 = EnclaveOpts::new(&mut args);
		let parsed_args: Vec<_> = vec!["--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();

		assert_eq!(args, parsed_args);
		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
		assert_eq!(*opts2.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts2.parsed.single(PORT).unwrap(), "3999".to_string());
	}

	#[test]
	fn parse_cid_and_port() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
	}

	#[test]
	fn parse_pivot_file_and_quorum_file() {
		let pivot = "pivot.file";
		let secret = "secret.file";
		let ephemeral = "ephemeral.file";
		let mut args: Vec<_> = vec![
			"binary",
			"--cid",
			"6",
			"--port",
			"3999",
			"--quorum-file",
			secret,
			"--pivot-file",
			pivot,
			"--ephemeral-file",
			ephemeral,
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(*opts.parsed.single(CID).unwrap(), "6");
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999");
		assert_eq!(opts.quorum_file(), secret);
		assert_eq!(opts.pivot_file(), pivot);
		assert_eq!(opts.ephemeral_file(), ephemeral);
	}

	#[test]
	fn parse_usock() {
		let mut args: Vec<_> = vec!["binary", "--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(opts.addr(), SocketAddress::new_unix("./test.sock"));
	}

	#[test]
	#[cfg(feature = "async")]
	fn parse_pool_size() {
		let mut args: Vec<_> =
			vec!["binary", "--usock", "./test.sock", "--pool-size", "7"]
				.into_iter()
				.map(String::from)
				.collect();
		let opts = EnclaveOpts::new(&mut args);

		let pool = opts.async_pool(false);
		assert_eq!(pool.len(), 7);
	}

	#[test]
	fn parse_manifest_file() {
		let mut args: Vec<_> = vec!["binary", "--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(opts.manifest_file(), MANIFEST_FILE.to_string());

		let mut args: Vec<_> = vec![
			"binary",
			"--usock",
			"./test.sock",
			"--manifest-file",
			"brawndo",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(opts.manifest_file(), "brawndo".to_string());
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
		let _opts = EnclaveOpts::new(&mut args);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MissingInput(\"port\")"]
	fn panic_on_not_enough_opts() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6"]
			.into_iter()
			.map(String::from)
			.collect();
		let _opts = EnclaveOpts::new(&mut args);
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
	#[should_panic = "Entered invalid CLI args: UnexpectedInput(\"--durp\")"]
	fn panic_when_mistyped_cid() {
		let mut args: Vec<_> =
			vec!["--durp"].into_iter().map(String::from).collect();
		let _opts = EnclaveOpts::new(&mut args);
	}
}
