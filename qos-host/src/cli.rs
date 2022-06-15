//! Command line interface for creating a host server and helpers for parsing
//! host specific command line arguments.

use std::{env, net::SocketAddr};

use qos_core::cli::EnclaveOptions;
use regex::Regex;

use crate::HostServer;

const IP_REGEX: &str = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$";

/// CLI options for starting a host server
#[derive(Clone, Debug, PartialEq)]
pub struct HostServerOptions {
	enclave: EnclaveOptions,
	host: HostOptions,
}

impl HostServerOptions {
	fn new() -> Self {
		Self { enclave: EnclaveOptions::new(), host: HostOptions::new() }
	}
}

/// CLI options for host IP address and Port.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct HostOptions {
	ip: Option<[u8; 4]>,
	port: Option<u16>,
}

impl HostOptions {
	/// Create a new instance of [`self`].
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Get the host server url.
	///
	/// # Panics
	///
	/// Panics if the url cannot be parsed from options
	#[must_use]
	pub fn url(&self) -> String {
		if let Self { ip: Some(ip), port: Some(port) } = self {
			return format!(
				"http://{}.{}.{}.{}:{}",
				ip[0], ip[1], ip[2], ip[3], port
			);
		}

		panic!("Couldn't parse URL from options.")
	}

	/// Get the resource path.
	#[must_use]
	pub fn path(&self, path: &str) -> String {
		let url = self.url();
		format!("{}/{}", url, path)
	}

	/// Parse host options.
	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_ip(cmd, arg);
		self.parse_port(cmd, arg);
	}

	fn parse_ip(&mut self, cmd: &str, arg: &str) {
		if cmd == "--host-ip" {
			let re = Regex::new(IP_REGEX)
				.expect("Could not parse value from `--host-ip`");
			let mut iter = re.captures_iter(arg);

			let parse = |string: &str| {
				string
					.to_string()
					.parse::<u8>()
					.expect("Could not parse value from `--host-ip`")
			};

			if let Some(cap) = iter.next() {
				let ip1 = parse(&cap[1]);
				let ip2 = parse(&cap[2]);
				let ip3 = parse(&cap[3]);
				let ip4 = parse(&cap[4]);
				self.ip = Some([ip1, ip2, ip3, ip4]);
			}
		}
	}

	fn parse_port(&mut self, cmd: &str, arg: &str) {
		if cmd == "--host-port" {
			self.port = arg
				.parse::<u16>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--port`")
				})
				.ok();
		}
	}
}

/// Host server command line interface.
///
/// # Options
///
/// * `--host-port` - the port for the host server to bind (ex: `3000`).
/// * `--host-ip` - the ip address the host server will bind to (ex:
///   `127.0.0.1`)
/// * `--port` - the port the enclave socket is listening on (only for VSOCK)
/// * `--cid` - context identifier for the enclave socket (only for VSOCK)
/// * `--usock` - name of the socket file (ex: `dev.sock`) (only for unix
///   sockets)
pub struct CLI;
impl CLI {
	/// Execute the command line interface.
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);
		let options = parse_args(&args);
		let addr = host_addr_from_options(options.host);
		let enclave_addr = options.enclave.addr();
		HostServer::new_with_socket_addr(enclave_addr, addr).serve().await;
	}
}

fn parse_args(args: &[String]) -> HostServerOptions {
	let mut options = HostServerOptions::new();

	let mut chunks = args.chunks_exact(2);
	assert!(chunks.remainder().is_empty(), "Unexepected number of arguments");
	while let Some([cmd, arg]) = chunks.next() {
		options.host.parse(cmd, arg);
		options.enclave.parse(cmd, arg);
	}

	options
}

fn host_addr_from_options(options: HostOptions) -> SocketAddr {
	if let HostOptions { ip: Some(ip), port: Some(port), .. } = options {
		SocketAddr::from((ip, port))
	} else {
		panic!("Invalid host address options")
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_ip_with_regex() {
		expect_ip("1.1.1.1", [1, 1, 1, 1]);
		expect_ip("1.2.3.4", [1, 2, 3, 4]);
		expect_ip("12.34.56.78", [12, 34, 56, 78]);
		expect_ip("111.222.244.255", [111, 222, 244, 255]);
	}

	#[test]
	#[should_panic]
	fn no_parse_ip() {
		expect_ip("something111.222.244.255", [111, 222, 244, 255]);
	}

	fn expect_ip(arg: &str, expected: [u8; 4]) {
		let mut options = HostOptions::new();
		options.parse_ip("--host-ip", arg);

		if let Some(ip) = options.ip {
			assert_eq!(ip[0], expected[0]);
			assert_eq!(ip[1], expected[1]);
			assert_eq!(ip[2], expected[2]);
			assert_eq!(ip[3], expected[3]);
		} else {
			panic!("Couldn't parse ip address");
		}
	}
}
