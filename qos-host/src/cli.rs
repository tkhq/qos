// Enclave socket address
// Port/Host bindings
use std::{env, net::SocketAddr};

use qos_core::{
	cli::{parse_enclave_options, EnclaveOptions},
	io::SocketAddress,
};
use regex::Regex;

use crate::HostServer;

const IP_REGEX: &'static str = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$";

#[derive(Clone, Debug, PartialEq)]
pub struct HostOptions {
	enclave: EnclaveOptions,
	ip: Option<[u8; 4]>,
	port: Option<u16>,
}

impl HostOptions {
	fn new() -> Self {
		Self { enclave: EnclaveOptions::new(), ip: None, port: None }
	}
}

pub struct CLI;
impl CLI {
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);
		let options = parse_args(args);
		let addr = host_addr_from_options(options.clone());
		let enclave_addr = enclave_addr_from_options(options.clone());
		HostServer::new_with_socket_addr(enclave_addr, addr)
			.serve()
			.await
			.unwrap();
	}
}

fn parse_args(args: Vec<String>) -> HostOptions {
	let mut options = HostOptions::new();

	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexepected number of arguments")
	}
	while let Some([cmd, arg]) = chunks.next() {
		parse_enclave_options(cmd.clone(), arg.clone(), &mut options.enclave);
		parse_host_addr(cmd, arg, &mut options);
	}

	options
}

fn parse_host_addr(cmd: &str, arg: &str, options: &mut HostOptions) {
	parse_ip(&cmd, &arg, options);
	parse_port(&cmd, &arg, options);
}

fn parse_ip(cmd: &str, arg: &str, options: &mut HostOptions) {
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
				options.ip = Some([ip1, ip2, ip3, ip4]);
			}
		}
		_ => {}
	}
}

fn parse_port(cmd: &str, arg: &str, options: &mut HostOptions) {
	match cmd {
		"--host-port" => {
			options.port = arg
				.parse::<u16>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--port`")
				})
				.ok();
		}
		_ => {}
	}
}

fn enclave_addr_from_options(options: HostOptions) -> SocketAddress {
	qos_core::cli::addr_from_options(options.enclave)
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
		parse_ip(&"--host-ip", arg, &mut options);

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
