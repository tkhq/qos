// Enclave socket address
// Port/Host bindings
use std::{env, net::SocketAddr};

use qos_core::cli::EnclaveOptions;
use regex::Regex;

use crate::HostServer;

const IP_REGEX: &'static str = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$";

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

#[derive(Clone, Debug, PartialEq)]
pub struct HostOptions {
	ip: Option<[u8; 4]>,
	port: Option<u16>,
}

impl HostOptions {
	pub fn new() -> Self {
		Self { ip: None, port: None }
	}

	pub fn url(&self) -> String {
		if let Self { ip: Some(ip), port: Some(port) } = self.clone() {
			return format!(
				"http://{}.{}.{}.{}:{}",
				ip[0], ip[1], ip[2], ip[3], port
			)
		} else {
			panic!("Couldn't parse URL from options.")
		}
	}

	pub fn path(&self, path: &str) -> String {
		let url = self.url();
		format!("{}/{}", url, path)
	}

	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_ip(cmd, arg);
		self.parse_port(cmd, arg);
	}

	pub fn parse_ip(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--host-ip" => {
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
			_ => {}
		}
	}

	pub fn parse_port(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--host-port" => {
				self.port = arg
					.parse::<u16>()
					.map_err(|_| {
						panic!("Could not parse provided value for `--port`")
					})
					.ok();
			}
			_ => {}
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
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);
		let options = parse_args(args);
		let addr = host_addr_from_options(options.host.clone());
		let enclave_addr = options.enclave.addr();
		HostServer::new_with_socket_addr(enclave_addr, addr)
			.serve()
			.await
			.unwrap();
	}
}

pub fn parse_args(args: Vec<String>) -> HostServerOptions {
	let mut options = HostServerOptions::new();

	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexepected number of arguments")
	}
	while let Some([cmd, arg]) = chunks.next() {
		options.host.parse(cmd, arg);
		options.enclave.parse(cmd, arg);
	}

	options
}

pub fn host_addr_from_options(options: HostOptions) -> SocketAddr {
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
		options.parse_ip(&"--host-ip", arg);

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
