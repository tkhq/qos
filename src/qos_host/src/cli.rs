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
const ENDPOINT_BASE_PATH: &str = "endpoint-base-path";
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
			.token(
				Token::new(ENDPOINT_BASE_PATH, "base path for all endpoints. e.g. <BASE>/enclave-health")
					.takes_value(true)
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
		format!("{url}/{path}")
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
				self.to_host_flag(),
			),
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

	fn base_path(&self) -> Option<String> {
		self.parsed.single(ENDPOINT_BASE_PATH).map(Clone::clone)
	}

	#[cfg(feature = "vm")]
	fn include_vsock_to_host(&self) -> Option<bool> {
		self.parsed.single(VSOCK_TO_HOST).as_ref().map(|s| s.parse()).map(|r| {
			r.expect("could not parse `--vsock-to-host`. Valid args are true or false")
		})
	}

	#[cfg(feature = "vm")]
	fn to_host_flag(&self) -> u8 {
		use sysinfo::{System, SystemExt};

		let sys = System::new_all();
		let kernel_version =
			sys.kernel_version().expect("The kernel version exists");
		println!(
			"System name:             {:?}",
			sys.name().expect("sys name exists")
		);
		println!("System kernel version:   {:?}", kernel_version);
		println!(
			"System OS version:       {:?}",
			sys.os_version().expect("os version exists")
		);
		println!("System host name:        {:?}", sys.host_name());

		let include = if let Some(include) = self.include_vsock_to_host() {
			include
		} else {
			Self::kernel_version_requires_to_host(kernel_version)
		};

		if include {
			println!("Configuring vsock with VMADDR_FLAG_TO_HOST.");
			qos_core::io::VMADDR_FLAG_TO_HOST
		} else {
			println!("Configuring vsock with VMADDR_NO_FLAGS.");
			qos_core::io::VMADDR_NO_FLAGS
		}
	}

	#[cfg(feature = "vm")]
	fn kernel_version_requires_to_host(kernel_version: String) -> bool {
		// we expect something of the form 6.1.37-nitro
		let parts: Vec<_> = kernel_version.split('.').collect();
		let major = parts[0]
			.parse::<u32>()
			.expect("failed to parse kernel major version");
		let minor = parts[1]
			.parse::<u32>()
			.expect("failed to parse kernel minor version");

		(minor >= 1 && major == 6) || major > 6
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
			HostServer::new(
				options.enclave_addr(),
				options.host_addr(),
				options.base_path(),
			)
			.serve()
			.await;
		}
	}
}

#[cfg(test)]
#[cfg(feature = "vm")]
mod test {
	use super::*;

	#[test]
	fn build_vsock() {
		let mut args: Vec<_> = vec![
			"binary",
			"--cid",
			"6",
			"--port",
			"3999",
			"--host-ip",
			"0.0.0.0",
			"--host-port",
			"3000",
			"--vsock-to-host",
			"false",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = HostOptions::new(&mut args);

		assert_eq!(
			opts.enclave_addr(),
			qos_core::io::SocketAddress::new_vsock(6, 3999, 0)
		);

		let mut args: Vec<_> = vec![
			"binary",
			"--cid",
			"6",
			"--port",
			"3999",
			"--host-ip",
			"0.0.0.0",
			"--host-port",
			"3000",
			"--vsock-to-host",
			"true",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = HostOptions::new(&mut args);

		assert_eq!(
			opts.enclave_addr(),
			qos_core::io::SocketAddress::new_vsock(6, 3999, 1)
		);
	}
}
