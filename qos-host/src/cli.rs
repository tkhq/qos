//! Command line interface for running a QOS Host server.

use std::{
	env,
	net::{IpAddr, Ipv4Addr, SocketAddr},
	str::FromStr,
};

use qos_core::{
	cli::{CID, PORT, USOCK},
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};

use crate::HostServer;

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";

struct HostParser;
impl GetParserForOptions for HostParser {
	fn parser() -> Parser {
		Parser::new()
			.token(
				Token::new(CID, "context identifier for the enclave socket (only for VSOCK)")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(PORT),
			)
			.token(
				Token::new(PORT, "the port the enclave socket is listening on (only for VSOCK)")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(CID),
			)
			.token(
				Token::new(USOCK, "name of the socket file (ex: `dev.sock`) (only for unix sockets)")
					.takes_value(true)
					.forbids(vec!["port", "cid"])
			)
			.token(
				Token::new(HOST_IP, "IP address this server should listen on")
					.takes_value(true)
					.required(true)
			)
			.token(
				Token::new(HOST_PORT, "IP address this server should listen on")
					.takes_value(true)
					.required(true)
			)
	}
}

/// CLI options for starting a host server.
#[derive(Clone, Debug, PartialEq)]
pub struct HostOptions {
	parsed: Parser,
}

impl HostOptions {
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<HostParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Get the host server url.
	///
	/// # Panics
	///
	/// Panics if the url cannot be parsed from options
	#[must_use]
	pub fn url(&self) -> String {
		format!("http://{}:{}", self.ip(), self.port())
	}

	/// Get the resource path.
	#[must_use]
	pub fn path(&self, path: &str) -> String {
		let url = self.url();
		format!("{}/{}", url, path)
	}

	/// Address the host server should listen on.
	#[must_use]
	pub fn host_addr(&self) -> SocketAddr {
		let ip = Ipv4Addr::from_str(&self.ip())
			.expect("Could not parser ip to IP v4");
		let port =
			self.port().parse::<u16>().expect("Could not parse port to u16");
		SocketAddr::new(IpAddr::V4(ip), port)
	}

	/// Get the `SocketAddress` for the enclave server.
	///
	/// # Panics
	///
	/// Panics if the options are not valid for exactly one of unix or vsock.
	#[must_use]
	pub fn enclave_addr(&self) -> SocketAddress {
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

	fn ip(&self) -> String {
		self.parsed.single(HOST_IP).expect("required arg").clone()
	}

	fn port(&self) -> String {
		self.parsed.single(HOST_PORT).expect("required arg").clone()
	}
}

/// Host server command line interface.
pub struct CLI;
impl CLI {
	/// Execute the command line interface.
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let options = HostOptions::new(&mut args);

		if options.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if options.parsed.help() {
			println!("{}", options.parsed.info());
		} else {
			HostServer::new(options.enclave_addr(), options.host_addr())
				.serve()
				.await;
		}
	}
}
