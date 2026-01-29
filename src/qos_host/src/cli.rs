//! Command line interface for running a QOS Host server.

use std::{
	env,
	net::{IpAddr, Ipv4Addr, SocketAddr},
	str::FromStr,
	time::Duration,
};

use qos_core::{
	cli::{CID, PORT, USOCK},
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const ENDPOINT_BASE_PATH: &str = "endpoint-base-path";
const VSOCK_TO_HOST: &str = "vsock-to-host";
const SOCKET_TIMEOUT: &str = "socket-timeout";

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
					.forbids(vec![PORT, CID])
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
				Token::new(SOCKET_TIMEOUT, "maximum time in ms a connect to the USOCK/VSOCK will take")
					.takes_value(true)
					.default_value(qos_core::DEFAULT_SOCKET_TIMEOUT_MS)
			)
			.token(
				Token::new(VSOCK_TO_HOST, "whether to add the to-host svm flag to the enclave vsock connection. Valid options are `true` or `false`")
					.takes_value(true)
					.required(false)
					.forbids(vec![USOCK])
			)
	}
}

/// CLI options for starting a host server.
#[derive(Clone, Debug, PartialEq)]
pub struct HostOpts {
	parsed: Parser,
}

impl HostOpts {
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
	/// # Panics
	/// Panics if the IP string cannot be parsed into an IPv4.
	#[must_use]
	pub fn host_addr(&self) -> SocketAddr {
		let ip = Ipv4Addr::from_str(&self.ip())
			.expect("Could not parser ip to IP v4");
		let port =
			self.port().parse::<u16>().expect("Could not parse port to u16");
		SocketAddr::new(IpAddr::V4(ip), port)
	}

	pub(crate) fn socket_timeout(&self) -> Duration {
		let default_timeout = &qos_core::DEFAULT_SOCKET_TIMEOUT_MS.to_owned();
		let timeout_str =
			self.parsed.single(SOCKET_TIMEOUT).unwrap_or(default_timeout);
		Duration::from_millis(
			timeout_str.parse().expect("invalid timeout value"),
		)
	}

	/// Create a new `StreamPool` using the list of `SocketAddress` for the qos host.
	pub(crate) fn enclave_socket(
		&self,
	) -> Result<SocketAddress, qos_core::io::IOError> {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(feature = "vm")]
			(Some(c), Some(p), None) => {
				let c = c.parse().map_err(|_| {
					qos_core::io::IOError::ConnectAddressInvalid
				})?;
				let p = p.parse().map_err(|_| {
					qos_core::io::IOError::ConnectAddressInvalid
				})?;

				Ok(SocketAddress::new_vsock(c, p, self.to_host_flag()))
			}
			(None, None, Some(u)) => Ok(SocketAddress::new_unix(u)),

			_ => panic!("Invalid socket opts"),
		}
	}

	fn ip(&self) -> String {
		self.parsed.single(HOST_IP).expect("required arg").clone()
	}

	fn port(&self) -> String {
		self.parsed.single(HOST_PORT).expect("required arg").clone()
	}

	fn base_path(&self) -> Option<String> {
		self.parsed.single(ENDPOINT_BASE_PATH).cloned()
	}

	#[cfg(feature = "vm")]
	fn to_host_flag(&self) -> u8 {
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
	/// # Panics
	/// If pool creation fails
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let options = HostOpts::new(&mut args);

		if options.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if options.parsed.help() {
			println!("{}", options.parsed.info());
		} else {
			crate::host::HostServer::new(
				options.enclave_socket().expect("invalid enclave socket"),
				options.socket_timeout(),
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
	fn parse_is_idempotent() {
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
		let opts = HostOpts::new(&mut args);
		let opts2 = HostOpts::new(&mut args);

		let parsed_args: Vec<_> = vec![
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

		assert_eq!(args, parsed_args);
		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
		assert_eq!(
			*opts.parsed.single(HOST_IP).unwrap(),
			"0.0.0.0".to_string()
		);
		assert_eq!(*opts.parsed.single(HOST_PORT).unwrap(), "3000".to_string());
		assert_eq!(
			*opts.parsed.single(VSOCK_TO_HOST).unwrap(),
			"false".to_string()
		);

		assert_eq!(*opts2.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts2.parsed.single(PORT).unwrap(), "3999".to_string());
		assert_eq!(
			*opts2.parsed.single(HOST_IP).unwrap(),
			"0.0.0.0".to_string()
		);
		assert_eq!(
			*opts2.parsed.single(HOST_PORT).unwrap(),
			"3000".to_string()
		);
		assert_eq!(
			*opts2.parsed.single(VSOCK_TO_HOST).unwrap(),
			"false".to_string()
		);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: UnexpectedInput(\"--durp\")"]
	fn panic_when_mistyped_cid() {
		let mut args: Vec<_> =
			vec!["--durp"].into_iter().map(String::from).collect();
		let _opts = HostOpts::new(&mut args);
	}

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
		let opts = HostOpts::new(&mut args);

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
		let opts = HostOpts::new(&mut args);

		assert_eq!(
			opts.enclave_addr(),
			qos_core::io::SocketAddress::new_vsock(6, 3999, 1)
		);
	}
}
