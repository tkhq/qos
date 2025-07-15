//! CLI for running a host proxy to provide remote connections.

use qos_core::{
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};

use qos_core::io::AsyncStreamPool;

use crate::async_proxy::AsyncProxyServer;

/// "cid"
pub const CID: &str = "cid";
/// "port"
pub const PORT: &str = "port";
/// "usock"
pub const USOCK: &str = "usock";
/// "pool-size"
pub const POOL_SIZE: &str = "pool-size";

/// CLI options for starting up the proxy.
#[derive(Default, Clone, Debug, PartialEq)]
pub(crate) struct ProxyOpts {
	pub(crate) parsed: Parser,
}

impl ProxyOpts {
	/// Create a new instance of [`Self`] with some defaults.
	pub(crate) fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<ProxyParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Create a new `AsyncPool` of `AsyncStream` using the list of `SocketAddress` for the enclave server and
	/// return the new `AsyncPool`.
	pub(crate) fn async_pool(
		&self,
	) -> Result<AsyncStreamPool, qos_core::io::IOError> {
		use qos_core::io::{TimeVal, TimeValLike};

		let pool_size: u32 = self
			.parsed
			.single(POOL_SIZE)
			.expect("invalid pool options")
			.parse()
			.expect("invalid pool_size specified");
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => {
				let c = c.parse::<u32>().unwrap();
				let p = p.parse::<u32>().unwrap();

				let address =
					SocketAddress::new_vsock(c, p, crate::io::VMADDR_NO_FLAGS);

				AsyncStreamPool::new(address, TimeVal::seconds(5), pool_size)
			}
			(None, None, Some(u)) => {
				let address = SocketAddress::new_unix(u);

				AsyncStreamPool::new(address, TimeVal::seconds(0), pool_size)
			}
			_ => panic!("Invalid socket opts"),
		}
	}

	/// Get the `SocketAddress` for the proxy server.
	///
	/// # Panics
	///
	/// Panics if the opts are not valid for exactly one of unix or vsock.
	#[allow(unused)]
	pub(crate) fn addr(&self) -> SocketAddress {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => SocketAddress::new_vsock(
				c.parse::<u32>().unwrap(),
				p.parse::<u32>().unwrap(),
				qos_core::io::VMADDR_NO_FLAGS,
			),
			(None, None, Some(u)) => SocketAddress::new_unix(u),
			_ => panic!("Invalid socket opts"),
		}
	}
}

/// Proxy CLI.
pub struct CLI;

impl CLI {
	/// Execute the enclave proxy CLI with the environment args in an async way.
	pub async fn execute() {
		use qos_core::async_server::AsyncSocketServer;

		let mut args: Vec<String> = std::env::args().collect();
		let opts = ProxyOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			let server = AsyncSocketServer::listen_proxy(
				opts.async_pool().expect("unable to create async socket pool"),
			)
			.await
			.expect("unable to get listen join handles");

			match tokio::signal::ctrl_c().await {
				Ok(_) => {
					eprintln!("handling ctrl+c the tokio way");
					server.terminate();
				}
				Err(err) => panic!("{err}"),
			}
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
			.token(
				Token::new(
					POOL_SIZE,
					"the pool size to use with all socket types.",
				)
				.takes_value(true)
				.forbids(vec!["port", "cid"])
				.default_value("1"),
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
	fn parse_pool_size() {
		let mut args: Vec<_> =
			vec!["binary", "--usock", "./test.sock", "--pool-size", "7"]
				.into_iter()
				.map(String::from)
				.collect();
		let opts = ProxyOpts::new(&mut args);

		let pool = opts.async_pool().unwrap();
		assert_eq!(pool.len(), 7);
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
