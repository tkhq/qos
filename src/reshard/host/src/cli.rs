//! Command line interface for reshard host.

use futures::future::join_all;
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

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const METRICS: &str = "metrics";
const METRICS_PORT: &str = "metrics-port";
const VSOCK_TO_HOST: &str = "vsock-to-host";

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
                Token::new(PORT, "port the enclave socket is listening on (only for VSOCK)")
                    .takes_value(true)
                    .forbids(vec![USOCK])
                    .requires(CID),
            )
            .token(
                Token::new(USOCK, "path of the socket file (only for unix sockets)")
                    .takes_value(true)
                    .forbids(vec!["port", "cid"]),
            )
            .token(
                Token::new(HOST_IP, "IP address this server should listen on")
                    .takes_value(true)
                    .required(true),
            )
            .token(
                Token::new(HOST_PORT, "port this server should listen on")
                    .takes_value(true)
                    .required(true),
            )
            .token(Token::new(METRICS, "enable metrics server").required(false))
            .token(
                Token::new(METRICS_PORT, "port to serve metrics")
                    .takes_value(true)
                    .requires(METRICS),
            )
            .token(
				Token::new(VSOCK_TO_HOST, "wether to add the to-host svm flag to the enclave vsock connection. Valid options are `true` or `false`")
					.takes_value(true)
					.forbids(vec![USOCK])
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
			.expect("provided invalid CLI args for Reshard host");

		Self { parsed }
	}

	/// Address the host server should listen on.
	fn host_addr(&self) -> SocketAddr {
		let ip = Ipv4Addr::from_str(&self.ip())
			.expect("could not parse ip to IP v4");
		let port =
			self.port().parse::<u16>().expect("could not parse port to u16");
		SocketAddr::new(IpAddr::V4(ip), port)
	}

	/// Address the metrics server should listen on.
	fn metrics_addr(&self) -> SocketAddr {
		let ip = Ipv4Addr::from_str(&self.ip())
			.expect("could not parse ip to IP v4");
		let port = self
			.metrics_port()
			.parse::<u16>()
			.expect("could not parse port to u16");
		SocketAddr::new(IpAddr::V4(ip), port)
	}

	/// Get the `SocketAddress` for the enclave server.
	///
	/// # Panics
	///
	/// Panics if the options are not valid for exactly one of unix or vsock.
	fn enclave_addr(&self) -> SocketAddress {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vsock")]
			(Some(c), Some(p), None) => SocketAddress::new_vsock(
				c.parse::<u32>().unwrap(),
				p.parse::<u32>().unwrap(),
				self.vsock_to_host_flag(),
			),
			(None, None, Some(u)) => SocketAddress::new_unix(u),
			_ => panic!("Invalid socket options"),
		}
	}

	fn ip(&self) -> String {
		self.parsed.single(HOST_IP).expect("host ip required").clone()
	}

	fn port(&self) -> String {
		self.parsed.single(HOST_PORT).expect("host port required").clone()
	}

	fn enable_metrics(&self) -> bool {
		self.parsed.flag(METRICS).unwrap_or(false)
	}

	fn metrics_port(&self) -> String {
		self.parsed.single(METRICS_PORT).expect("metrics port required").clone()
	}

	#[cfg(feature = "vsock")]
	fn vsock_to_host_flag(&self) -> u8 {
		let include = self
			.parsed
			.single(VSOCK_TO_HOST)
			.as_ref()
			.map(|s| s.parse())
			.map(|r| {
				r.expect("could not parse `--vsock-to-host`. Valid args are true or false")
			})
			.unwrap_or(false);

		if include {
			println!("Configuring vsock with VMADDR_FLAG_TO_HOST.");
			qos_core::io::VMADDR_FLAG_TO_HOST
		} else {
			println!("Configuring vsock with VMADDR_NO_FLAGS.");
			qos_core::io::VMADDR_NO_FLAGS
		}
	}
}

/// Host server command line interface.
pub struct CLI;
impl CLI {
	/// Execute the command line interface.
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let opts = HostOptions::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
			return;
		}

		if opts.parsed.help() {
			println!("{}", opts.parsed.info());
			return;
		}

		let mut handles = vec![];

		// host
		let host_addr = opts.host_addr();
		let enclave_addr = opts.enclave_addr();
		handles.push(tokio::spawn(async move {
			crate::host::Host::listen(host_addr, enclave_addr)
				.await
				.expect("`Host::listen` error");
		}));

		// metrics
		if opts.enable_metrics() {
			let metrics_addr = opts.metrics_addr();
			handles.push(tokio::spawn(async move {
				let collector = metrics::Collector::new();
				let metrics_server = metrics::Server::new();

				metrics_server.serve(metrics_addr, collector).await;
			}));
		}

		// Concurrently process the results and panic on error
		let results: Vec<_> = join_all(handles).await;
		for result in results {
			result.expect("Error: `Host::listen` error");
		}
	}
}
